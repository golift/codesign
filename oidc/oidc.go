// Package oidc verifies GitHub Actions OIDC tokens presented to signerd.
// A token is accepted only when its signature checks out against the issuer's
// JWKS, the issuer and audience match the daemon configuration, it has not
// expired, and its repository claim is on the operator's allowlist. The
// allowlist fails closed: an empty list rejects every token.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultIssuer is the issuer of GitHub Actions OIDC tokens on github.com.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

const (
	// keyCacheTTL is how long fetched JWKS keys are trusted. After it,
	// verification refreshes or fails closed — stale keys are never reused
	// past this window, even during an issuer outage.
	keyCacheTTL = 10 * time.Minute
	// refreshCooldown limits how often a JWKS refresh may be attempted.
	refreshCooldown = time.Minute
	// fetchTimeout bounds one JWKS/discovery HTTP round trip, even when the
	// caller supplies a client without its own timeout.
	fetchTimeout = 10 * time.Second
	// maxMetaBytes caps discovery and JWKS JSON so a compromised issuer
	// cannot fill memory.
	maxMetaBytes = 1 << 20
)

// Errors returned by Verify, beyond signature/claim errors from the JWT library.
var (
	ErrEmptyAllowlist = errors.New("allowed repositories list is empty, refusing all tokens")
	ErrNoAudience     = errors.New("no audience configured, refusing all tokens")
	ErrRepoNotAllowed = errors.New("repository is not on the allowed repositories list")
	ErrNoRepository   = errors.New("token has no repository claim")
	ErrNoKeyID        = errors.New("token header has no key ID")
	ErrUnknownKeyID   = errors.New("no issuer key matches the token key ID")
	ErrStaleKeys      = errors.New("issuer keys are stale and cannot be refreshed yet")
	ErrBadDiscovery   = errors.New("issuer discovery document has no jwks_uri")
	ErrJWKSHost       = errors.New("jwks_uri host does not match the configured issuer")

	// errCooldown is an internal signal that a refresh was rate-limited.
	errCooldown = errors.New("JWKS refresh attempted too recently")
	// errUnexpectedStatus reports a non-200 discovery or JWKS response.
	errUnexpectedStatus = errors.New("unexpected response status")
)

// Config controls token verification.
type Config struct {
	// Issuer is the OIDC issuer URL. Defaults to DefaultIssuer. The issuer's
	// discovery document provides the JWKS used to verify signatures.
	Issuer string
	// Audience must match the token's aud claim. Callers request their token
	// with this audience; conventionally the public URL of the signing host.
	Audience string
	// AllowedRepositories lists "Owner/repo" values (case-insensitive) whose
	// tokens may sign. Empty means nothing is allowed.
	AllowedRepositories []string
	// Client is the HTTP client for discovery and JWKS fetches. Optional.
	Client *http.Client
}

// Claims are the GitHub Actions token claims signerd cares about.
//
//nolint:tagliatelle // GitHub picked these JSON field names, not us.
type Claims struct {
	jwt.RegisteredClaims

	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Ref             string `json:"ref"`
	Workflow        string `json:"workflow"`
	JobWorkflowRef  string `json:"job_workflow_ref"`
	EventName       string `json:"event_name"`
	Actor           string `json:"actor"`
	RunID           string `json:"run_id"`
}

// Verifier verifies GitHub Actions OIDC tokens. Create one with New.
// It caches the issuer's JWKS and is safe for concurrent use.
type Verifier struct {
	config    Config
	mu        sync.RWMutex
	refreshMu sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetched   time.Time // last successful JWKS fetch.
	attempted time.Time // last JWKS fetch attempt, successful or not.
}

// New returns a Verifier for the provided configuration.
func New(config *Config) *Verifier {
	verifier := &Verifier{config: *config}

	if verifier.config.Issuer == "" {
		verifier.config.Issuer = DefaultIssuer
	}

	if verifier.config.Client == nil {
		verifier.config.Client = &http.Client{Timeout: fetchTimeout}
	}

	return verifier
}

// Verify checks one bearer token and returns its claims when every gate
// passes: RS256 signature against the issuer's JWKS, issuer, audience,
// expiration, and the repository allowlist.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if len(v.config.AllowedRepositories) == 0 {
		return nil, ErrEmptyAllowlist
	}

	// jwt.WithAudience skips validation when the expected value is empty,
	// which would accept a token minted for any audience. Fail closed.
	if v.config.Audience == "" {
		return nil, ErrNoAudience
	}

	claims := &Claims{}

	_, err := jwt.ParseWithClaims(token, claims, func(parsed *jwt.Token) (any, error) {
		keyID, _ := parsed.Header["kid"].(string)
		if keyID == "" {
			return nil, ErrNoKeyID
		}

		return v.key(ctx, keyID)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	if claims.Repository == "" {
		return nil, ErrNoRepository
	}

	allowed := slices.ContainsFunc(v.config.AllowedRepositories, func(repo string) bool {
		return strings.EqualFold(repo, claims.Repository)
	})
	if !allowed {
		return nil, fmt.Errorf("%w: %s", ErrRepoNotAllowed, claims.Repository)
	}

	return claims, nil
}

// key returns the issuer public key with the provided ID. A still-fresh JWKS
// is authoritative: unknown key IDs are rejected without another fetch
// (kid is attacker-controlled and arrives before the signature check).
// Cache reads do not wait on in-flight HTTP. After the TTL, verification
// refreshes or fails closed; keys are never trusted past keyCacheTTL.
func (v *Verifier) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, cached := v.keys[keyID]
	fresh := v.cacheFresh()
	v.mu.RUnlock()

	if cached && fresh {
		return key, nil
	}

	if fresh {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}

	err := v.refresh(ctx)
	if err != nil {
		if cached {
			return nil, ErrStaleKeys
		}

		if errors.Is(err, errCooldown) {
			return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
		}

		return nil, err
	}

	v.mu.RLock()
	key, ok := v.keys[keyID]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}

	return key, nil
}

func (v *Verifier) cacheFresh() bool {
	return !v.fetched.IsZero() && time.Since(v.fetched) < keyCacheTTL
}

// refresh fetches the JWKS unless another attempt already ran within the
// cooldown or another goroutine just refreshed. HTTP runs without v.mu so
// cached verifications keep moving during a slow issuer.
func (v *Verifier) refresh(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	v.mu.RLock()
	fresh := v.cacheFresh()
	cooling := time.Since(v.attempted) < refreshCooldown && !v.attempted.IsZero()
	v.mu.RUnlock()

	if fresh {
		return nil
	}

	if cooling {
		return errCooldown
	}

	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	keys, err := v.loadKeys(fetchCtx)

	v.mu.Lock()
	v.attempted = time.Now()

	if err == nil {
		v.keys = keys
		v.fetched = time.Now()
	}

	v.mu.Unlock()

	return err
}

// loadKeys fetches discovery + JWKS without holding v.mu.
func (v *Verifier) loadKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	discovery := struct {
		JWKSURI string `json:"jwks_uri"` //nolint:tagliatelle // OIDC spec name.
	}{}

	err := v.getJSON(ctx, strings.TrimSuffix(v.config.Issuer, "/")+"/.well-known/openid-configuration", &discovery)
	if err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}

	if discovery.JWKSURI == "" {
		return nil, ErrBadDiscovery
	}

	err = v.checkJWKSURI(discovery.JWKSURI)
	if err != nil {
		return nil, err
	}

	keySet := struct {
		Keys []struct {
			Type     string `json:"kty"`
			ID       string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}{}

	err = v.getJSON(ctx, discovery.JWKSURI, &keySet)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(keySet.Keys))

	for _, key := range keySet.Keys {
		if key.Type != "RSA" || key.ID == "" {
			continue
		}

		modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil {
			return nil, fmt.Errorf("decoding key %s modulus: %w", key.ID, err)
		}

		exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil {
			return nil, fmt.Errorf("decoding key %s exponent: %w", key.ID, err)
		}

		keys[key.ID] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}
	}

	return keys, nil
}

// checkJWKSURI refuses a JWKS hosted on a different origin than the
// configured issuer, so a compromised discovery document cannot redirect
// fetches at an attacker-controlled URL.
func (v *Verifier) checkJWKSURI(jwks string) error {
	issuerURL, err := url.Parse(v.config.Issuer)
	if err != nil {
		return fmt.Errorf("parsing issuer: %w", err)
	}

	jwksURL, err := url.Parse(jwks)
	if err != nil {
		return fmt.Errorf("parsing jwks_uri: %w", err)
	}

	if jwksURL.Scheme != issuerURL.Scheme || jwksURL.Host != issuerURL.Host {
		return fmt.Errorf("%w: %s", ErrJWKSHost, jwksURL.Host)
	}

	return nil
}

// getJSON fetches a URL and decodes the JSON response into output.
func (v *Verifier) getJSON(ctx context.Context, rawURL string, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := v.config.Client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %s", errUnexpectedStatus, rawURL, resp.Status)
	}

	err = json.NewDecoder(io.LimitReader(resp.Body, maxMetaBytes)).Decode(output)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", rawURL, err)
	}

	return nil
}
