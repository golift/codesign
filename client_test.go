package codesign_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign"
)

func TestNewRequiresURL(t *testing.T) {
	t.Parallel()

	_, err := codesign.New(&codesign.Config{})
	require.ErrorIs(t, err, codesign.ErrNoURL)

	_, err = codesign.New(nil)
	require.ErrorIs(t, err, codesign.ErrNoURL)
}

func TestSignFile(t *testing.T) {
	t.Parallel()

	var gotHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, codesign.SignPath, req.URL.Path)
		gotHeaders = req.Header.Clone()

		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)

		_, _ = resp.Write(append(body, []byte(" SIGNED")...))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL + "/", Token: "jwt-token"})
	require.NoError(t, err)

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	require.NoError(t, os.WriteFile(input, []byte("MZ binary"), 0o600))

	err = client.SignFile(t.Context(), input, "", &codesign.SignOptions{
		Name: "My App",
		URL:  "https://app.example.com",
	})
	require.NoError(t, err)

	signed, err := os.ReadFile(input)
	require.NoError(t, err)
	assert.Equal(t, "MZ binary SIGNED", string(signed), "in-place signing replaces the input file")

	assert.Equal(t, "app.exe", gotHeaders.Get(codesign.HeaderFilename))
	assert.Equal(t, "My App", gotHeaders.Get(codesign.HeaderName))
	assert.Equal(t, "https://app.example.com", gotHeaders.Get(codesign.HeaderURL))
	assert.Equal(t, "Bearer jwt-token", gotHeaders.Get("Authorization"))
}

func TestSignFileSeparateOutput(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		_, _ = resp.Write([]byte("signed bytes"))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL})
	require.NoError(t, err)

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	output := filepath.Join(dir, "app-signed.exe")

	require.NoError(t, os.WriteFile(input, []byte("MZ binary"), 0o600))

	require.NoError(t, client.SignFile(t.Context(), input, output, nil))

	original, err := os.ReadFile(input)
	require.NoError(t, err)
	assert.Equal(t, "MZ binary", string(original), "input untouched when an output path is given")

	signed, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "signed bytes", string(signed))
}

func TestSignFilePreservesMode(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits to preserve")
	}

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		_, _ = resp.Write([]byte("signed"))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL})
	require.NoError(t, err)

	input := filepath.Join(t.TempDir(), "app.exe")
	require.NoError(t, os.WriteFile(input, []byte("MZ binary"), 0o755)) //nolint:gosec // The exec bit is the point.

	require.NoError(t, client.SignFile(t.Context(), input, "", nil))

	info, err := os.Stat(input)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "executable bit must survive in-place signing")
}

func TestNewRejectsPlaintextRemoteURL(t *testing.T) {
	t.Parallel()

	_, err := codesign.New(&codesign.Config{URL: "http://sign.example.com", Token: "jwt"})
	require.ErrorIs(t, err, codesign.ErrInsecureURL)

	_, err = codesign.New(&codesign.Config{URL: "https://sign.example.com"})
	require.NoError(t, err)

	_, err = codesign.New(&codesign.Config{URL: "http://127.0.0.1:8750"})
	require.NoError(t, err)

	_, err = codesign.New(&codesign.Config{URL: "http://localhost:8750"})
	require.NoError(t, err)
}

func TestNewRejectsHalfKeyPair(t *testing.T) {
	t.Parallel()

	_, err := codesign.New(&codesign.Config{URL: "http://127.0.0.1:1", ClientKey: "key.pem"})
	require.ErrorIs(t, err, codesign.ErrHalfKeyPair)

	_, err = codesign.New(&codesign.Config{URL: "http://127.0.0.1:1", ClientCert: "cert.pem"})
	require.ErrorIs(t, err, codesign.ErrHalfKeyPair)
}

func TestSignNegativeRetriesStillSigns(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		_, _ = resp.Write([]byte("signed"))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL, Retries: -5})
	require.NoError(t, err)

	signed, err := client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.NoError(t, err)
	assert.Equal(t, "signed", string(signed), "negative retries must not skip the request loop")
}

func TestSignRetriesGatewayErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			http.Error(resp, "upstream not ready", http.StatusServiceUnavailable)

			return
		}

		_, _ = resp.Write([]byte("signed"))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL, Retries: 3})
	require.NoError(t, err)

	signed, err := client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.NoError(t, err)
	assert.Equal(t, "signed", string(signed))
	assert.Equal(t, int32(3), attempts.Load())
}

func TestSignDoesNotRetryAuthFailures(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(resp, "unauthorized: bad token", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL, Retries: 5})
	require.NoError(t, err)

	_, err = client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad token")
	assert.Equal(t, int32(1), attempts.Load(), "4xx responses must not retry")
}

func TestSignRejectsInvalidHeaderMetadata(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)

		_, _ = resp.Write([]byte("signed"))
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL, Retries: 5})
	require.NoError(t, err)

	// A Unix filename may contain a newline, which is not a valid header value.
	_, err = client.Sign(t.Context(), "app\n.exe", []byte("MZ"), nil)
	require.ErrorIs(t, err, codesign.ErrInvalidHeader)
	assert.Zero(t, attempts.Load(), "an invalid header must fail before any request or retry")

	_, err = client.Sign(t.Context(), "app.exe", []byte("MZ"), &codesign.SignOptions{Name: "bad\x00name"})
	require.ErrorIs(t, err, codesign.ErrInvalidHeader)
}

func TestSignDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var signHits atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc(codesign.SignPath, func(resp http.ResponseWriter, _ *http.Request) {
		signHits.Add(1)
		http.Redirect(resp, &http.Request{}, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(resp http.ResponseWriter, _ *http.Request) {
		_, _ = resp.Write([]byte("leaked-signed-bytes"))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL})
	require.NoError(t, err)

	signed, err := client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.Error(t, err, "a redirect must not be followed and accepted as the signed artifact")
	assert.NotContains(t, string(signed), "leaked")
	assert.Equal(t, int32(1), signHits.Load())
}

func TestSignErrorBodyIsCapped(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		http.Error(resp, strings.Repeat("x", 64<<10), http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL})
	require.NoError(t, err)

	_, err = client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.Error(t, err)
	assert.Less(t, len(err.Error()), 8<<10, "error bodies must not be copied unbounded")
	assert.NotContains(t, err.Error(), strings.Repeat("x", 8<<10))
}

func TestHealth(t *testing.T) {
	t.Parallel()

	healthy := atomic.Bool{}
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		assert.Equal(t, codesign.HealthPath, req.URL.Path)

		if healthy.Load() {
			_, _ = resp.Write([]byte("OK\n"))
		} else {
			http.Error(resp, "unhealthy: token unplugged", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(server.Close)

	client, err := codesign.New(&codesign.Config{URL: server.URL})
	require.NoError(t, err)

	err = client.Health(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token unplugged")

	healthy.Store(true)
	require.NoError(t, client.Health(t.Context()))
}

func TestMutualTLS(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := selfSignedCert(t)

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	require.True(t, clientCAs.AppendCertsFromPEM(certPEM))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		assert.NotEmpty(t, req.TLS.PeerCertificates, "server must see the client certificate")

		_, _ = resp.Write([]byte("signed"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	// Inline PEM for cert and CA, exercising both loadPEM paths.
	client, err := codesign.New(&codesign.Config{
		URL:        server.URL,
		ClientCert: string(certPEM),
		ClientKey:  string(keyPEM),
		RootCA:     string(certPEM),
	})
	require.NoError(t, err)

	signed, err := client.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.NoError(t, err)
	assert.Equal(t, "signed", string(signed))

	// Without a client certificate the handshake must fail.
	bare, err := codesign.New(&codesign.Config{URL: server.URL, RootCA: string(certPEM)})
	require.NoError(t, err)

	_, err = bare.Sign(t.Context(), "app.exe", []byte("MZ"), nil)
	require.Error(t, err, "mTLS server must reject clients without a certificate")
}

func TestFetchGitHubToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "https://sign.example.com", req.URL.Query().Get("audience"))
		assert.Equal(t, "Bearer runtime-token", req.Header.Get("Authorization"))

		_ = json.NewEncoder(resp).Encode(map[string]string{"value": "the-oidc-jwt"})
	}))
	t.Cleanup(server.Close)

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL+"/?api-version=2")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-token")

	token, err := codesign.FetchGitHubToken(t.Context(), "https://sign.example.com")
	require.NoError(t, err)
	assert.Equal(t, "the-oidc-jwt", token)
}

func TestFetchGitHubTokenWithoutExistingQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "https://sign.example.com", req.URL.Query().Get("audience"))

		_ = json.NewEncoder(resp).Encode(map[string]string{"value": "the-oidc-jwt"})
	}))
	t.Cleanup(server.Close)

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-token")

	token, err := codesign.FetchGitHubToken(t.Context(), "https://sign.example.com")
	require.NoError(t, err)
	assert.Equal(t, "the-oidc-jwt", token)
}

func TestFetchGitHubTokenEmptyValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(resp).Encode(map[string]string{"value": ""})
	}))
	t.Cleanup(server.Close)

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL+"/?api-version=2")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-token")

	_, err := codesign.FetchGitHubToken(t.Context(), "https://sign.example.com")
	require.ErrorIs(t, err, codesign.ErrEmptyOIDC)
}

func TestFetchGitHubTokenOutsideActions(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	_, err := codesign.FetchGitHubToken(t.Context(), "aud")
	require.ErrorIs(t, err, codesign.ErrNoActionsOIDC)
}

// selfSignedCert generates a certificate valid for server and client auth on
// 127.0.0.1, so one cert can play every role in the mTLS test.
func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "codesign-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
