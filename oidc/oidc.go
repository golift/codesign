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
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultIssuer is the issuer of GitHub Actions OIDC tokens on github.com.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

const (
	// keyCacheTTL is how long fetched JWKS keys are trusted before a refresh.
	keyCacheTTL = 10 * time.Minute
	// fetchTimeout bounds one JWKS/discovery HTTP round trip.
	fetchTimeout = 10 * time.Second
)

// Errors returned by Verify, beyond signature/claim errors from the JWT library.
var (
	ErrEmptyAllowlist = errors.New("allowed repositories list is empty, refusing all tokens")
	ErrRepoNotAllowed = errors.New("repository is not on the allowed repositories list")
	ErrNoRepository   = errors.New("token has no repository claim")
	ErrNoKeyID        = errors.New("token header has no key ID")
	ErrUnknownKeyID   = errors.New("no issuer key matches the token key ID")
	ErrBadDiscovery   = errors.New("issuer discovery document has no jwks_uri")
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
	config  Config
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
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

// key returns the issuer public key with the provided ID, fetching or
// refreshing the JWKS as needed.
func (v *Verifier) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if key, ok := v.keys[keyID]; ok && time.Since(v.fetched) < keyCacheTTL {
		return key, nil
	}

	err := v.fetchKeys(ctx)
	if err != nil {
		// Ride out a fetch blip when the key is already cached.
		if key, ok := v.keys[keyID]; ok {
			return key, nil
		}

		return nil, err
	}

	if key, ok := v.keys[keyID]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
}

// fetchKeys replaces the cached JWKS. The caller must hold the mutex.
func (v *Verifier) fetchKeys(ctx context.Context) error {
	discovery := struct {
		JWKSURI string `json:"jwks_uri"` //nolint:tagliatelle // OIDC spec name.
	}{}

	err := v.getJSON(ctx, strings.TrimSuffix(v.config.Issuer, "/")+"/.well-known/openid-configuration", &discovery)
	if err != nil {
		return fmt.Errorf("issuer discovery: %w", err)
	}

	if discovery.JWKSURI == "" {
		return ErrBadDiscovery
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
		return fmt.Errorf("fetching JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(keySet.Keys))

	for _, key := range keySet.Keys {
		if key.Type != "RSA" || key.ID == "" {
			continue
		}

		modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil {
			return fmt.Errorf("decoding key %s modulus: %w", key.ID, err)
		}

		exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil {
			return fmt.Errorf("decoding key %s exponent: %w", key.ID, err)
		}

		keys[key.ID] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}
	}

	v.keys = keys
	v.fetched = time.Now()

	return nil
}

// getJSON fetches a URL and decodes the JSON response into output.
func (v *Verifier) getJSON(ctx context.Context, url string, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := v.config.Client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %s", errUnexpectedStatus, url, resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(output)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", url, err)
	}

	return nil
}

// errUnexpectedStatus reports a non-200 discovery or JWKS response.
var errUnexpectedStatus = errors.New("unexpected response status")
