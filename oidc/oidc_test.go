package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign/oidc"
)

const (
	testKeyID    = "test-key-1"
	testAudience = "https://sign.example.com"
	testRepo     = "golift/codesign"
)

// issuer is a fake OIDC issuer: an httptest server with a discovery document,
// a JWKS containing one RSA key, and a helper to mint signed tokens.
type issuer struct {
	url      string
	key      *rsa.PrivateKey
	jwksHits atomic.Int32
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fake := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(resp http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(resp).Encode(map[string]string{"jwks_uri": fake.url + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(resp http.ResponseWriter, _ *http.Request) {
		fake.jwksHits.Add(1)

		_ = json.NewEncoder(resp).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": testKeyID,
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   "AQAB",
		}}})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	fake.url = server.URL

	return fake
}

// claims returns a valid set of GitHub-Actions-style claims for this issuer.
func (i *issuer) claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":        i.url,
		"aud":        testAudience,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"repository": testRepo,
		"actor":      "davidnewhall",
		"ref":        "refs/heads/main",
	}
}

// token mints a token signed by the issuer key.
func (i *issuer) token(t *testing.T, keyID string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	signed, err := token.SignedString(i.key)
	require.NoError(t, err)

	return signed
}

func TestVerify(t *testing.T) {
	t.Parallel()

	fake := newIssuer(t)

	tests := []struct {
		name          string
		allowlist     []string
		keyID         string
		emptyAudience bool
		mutate        func(jwt.MapClaims)
		wantErr       error
	}{
		{
			name:      "valid token",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
		},
		{
			name:      "repository match is case-insensitive",
			allowlist: []string{"GoLift/CodeSign"},
			keyID:     testKeyID,
		},
		{
			name:      "repository not allowed",
			allowlist: []string{"golift/other"},
			keyID:     testKeyID,
			wantErr:   oidc.ErrRepoNotAllowed,
		},
		{
			name:      "empty allowlist fails closed",
			allowlist: nil,
			keyID:     testKeyID,
			wantErr:   oidc.ErrEmptyAllowlist,
		},
		{
			name:          "empty audience fails closed",
			allowlist:     []string{testRepo},
			keyID:         testKeyID,
			emptyAudience: true,
			wantErr:       oidc.ErrNoAudience,
		},
		{
			name:      "wrong audience",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
			mutate:    func(claims jwt.MapClaims) { claims["aud"] = "https://evil.example.com" },
			wantErr:   jwt.ErrTokenInvalidAudience,
		},
		{
			name:      "wrong issuer",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
			mutate:    func(claims jwt.MapClaims) { claims["iss"] = "https://evil.example.com" },
			wantErr:   jwt.ErrTokenInvalidIssuer,
		},
		{
			name:      "expired token",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
			mutate:    func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Hour).Unix() },
			wantErr:   jwt.ErrTokenExpired,
		},
		{
			name:      "missing expiration",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
			mutate:    func(claims jwt.MapClaims) { delete(claims, "exp") },
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:      "missing key ID",
			allowlist: []string{testRepo},
			keyID:     "",
			wantErr:   oidc.ErrNoKeyID,
		},
		{
			name:      "unknown key ID",
			allowlist: []string{testRepo},
			keyID:     "who-dis",
			wantErr:   oidc.ErrUnknownKeyID,
		},
		{
			name:      "missing repository claim",
			allowlist: []string{testRepo},
			keyID:     testKeyID,
			mutate:    func(claims jwt.MapClaims) { delete(claims, "repository") },
			wantErr:   oidc.ErrNoRepository,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			audience := testAudience
			if test.emptyAudience {
				audience = ""
			}

			verifier := oidc.New(&oidc.Config{
				Issuer:              fake.url,
				Audience:            audience,
				AllowedRepositories: test.allowlist,
			})

			mapClaims := fake.claims()
			if test.mutate != nil {
				test.mutate(mapClaims)
			}

			claims, err := verifier.Verify(t.Context(), fake.token(t, test.keyID, mapClaims))
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				assert.Nil(t, claims)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, testRepo, claims.Repository)
			assert.Equal(t, "davidnewhall", claims.Actor)
			assert.Equal(t, "refs/heads/main", claims.Ref)
		})
	}
}

// TestVerifyRejectsWeakAlgorithms proves an attacker cannot bypass signature
// checks by presenting a token signed with a symmetric algorithm.
func TestVerifyRejectsWeakAlgorithms(t *testing.T) {
	t.Parallel()

	fake := newIssuer(t)
	verifier := oidc.New(&oidc.Config{
		Issuer:              fake.url,
		Audience:            testAudience,
		AllowedRepositories: []string{testRepo},
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, fake.claims())
	token.Header["kid"] = testKeyID
	signed, err := token.SignedString([]byte("guessable"))
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), signed)
	require.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

// TestVerifyGarbage proves non-JWT input is rejected without contacting the
// issuer.
func TestVerifyGarbage(t *testing.T) {
	t.Parallel()

	verifier := oidc.New(&oidc.Config{
		Issuer:              "http://127.0.0.1:1", // unreachable on purpose.
		Audience:            testAudience,
		AllowedRepositories: []string{testRepo},
	})

	_, err := verifier.Verify(t.Context(), "not-a-token")
	require.ErrorIs(t, err, jwt.ErrTokenMalformed)
}

// TestVerifyUnknownKeyIDRateLimited proves that attacker-controlled key IDs
// cannot generate a JWKS fetch per token: after one fetch, unknown IDs are
// rejected from cache until the refresh cooldown expires.
func TestVerifyUnknownKeyIDRateLimited(t *testing.T) {
	t.Parallel()

	fake := newIssuer(t)
	verifier := oidc.New(&oidc.Config{
		Issuer:              fake.url,
		Audience:            testAudience,
		AllowedRepositories: []string{testRepo},
	})

	for range 5 {
		_, err := verifier.Verify(t.Context(), fake.token(t, "bogus-kid", fake.claims()))
		require.ErrorIs(t, err, oidc.ErrUnknownKeyID)
	}

	assert.Equal(t, int32(1), fake.jwksHits.Load(), "bogus key IDs must not trigger repeated JWKS fetches")

	// A real token still verifies from the same fetch.
	_, err := verifier.Verify(t.Context(), fake.token(t, testKeyID, fake.claims()))
	require.NoError(t, err)
	assert.Equal(t, int32(1), fake.jwksHits.Load())
}

func TestVerifyRejectsJWKSOnOtherHost(t *testing.T) {
	t.Parallel()

	evil := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		t.Error("JWKS fetch must not follow a foreign jwks_uri")
		http.Error(resp, "nope", http.StatusTeapot)
	}))
	t.Cleanup(evil.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(resp http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(resp).Encode(map[string]string{"jwks_uri": evil.URL + "/jwks"})
	})

	issuer := httptest.NewServer(mux)
	t.Cleanup(issuer.Close)

	verifier := oidc.New(&oidc.Config{
		Issuer:              issuer.URL,
		Audience:            testAudience,
		AllowedRepositories: []string{testRepo},
	})

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":        issuer.URL,
		"aud":        testAudience,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"repository": testRepo,
	})
	token.Header["kid"] = testKeyID

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), signed)
	require.ErrorIs(t, err, oidc.ErrJWKSHost)
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	verifier := oidc.New(&oidc.Config{Audience: testAudience})
	require.NotNil(t, verifier)

	// The default issuer is GitHub's; a garbage token fails long before any
	// network traffic, proving defaults do not panic.
	_, err := verifier.Verify(t.Context(), "nope")
	require.Error(t, err)
}
