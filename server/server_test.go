package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign"
	"golift.io/codesign/oidc"
	"golift.io/codesign/server"
	"golift.io/codesign/signer"
)

const (
	remotePeer = "203.0.113.9:54321" // TEST-NET address: never loopback.
	goodToken  = "good-token"
	peBody     = "MZ this is a fake portable executable"
)

// stubVerifier accepts exactly one token.
type stubVerifier struct{}

var errBadToken = errors.New("token rejected by stub")

func (stubVerifier) Verify(_ context.Context, token string) (*oidc.Claims, error) {
	if token == goodToken {
		return &oidc.Claims{Repository: "golift/codesign"}, nil
	}

	return nil, errBadToken
}

// newServer returns a handler wired to a Fake signer and the stub verifier.
func newServer(t *testing.T, fake *signer.Fake) http.Handler {
	t.Helper()

	return server.New(&server.Config{
		Signer:   fake,
		Verifier: stubVerifier{},
		MaxBody:  1024,
		WorkDir:  t.TempDir(),
	}).Handler()
}

// signRequest builds a POST /v1/sign request from the fake remote peer.
func signRequest(ctx context.Context, body string, headers map[string]string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, codesign.SignPath, strings.NewReader(body))
	req.RemoteAddr = remotePeer

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	return req
}

func TestHealth(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	recorder := httptest.NewRecorder()
	healthReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, codesign.HealthPath, http.NoBody)
	handler.ServeHTTP(recorder, healthReq)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "OK\n", recorder.Body.String())

	fake.SetHealthErr(errors.New("token unplugged"))

	recorder = httptest.NewRecorder()
	healthReq = httptest.NewRequestWithContext(t.Context(), http.MethodGet, codesign.HealthPath, http.NoBody)
	handler.ServeHTTP(recorder, healthReq)
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Equal(t, "unhealthy\n", recorder.Body.String(), "unauthenticated health must not leak backend errors")
}

func TestSignWithToken(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, map[string]string{
		"Authorization":         "Bearer " + goodToken,
		codesign.HeaderFilename: "notifiarr.amd64.exe",
		codesign.HeaderName:     "Notifiarr",
		codesign.HeaderURL:      "https://notifiarr.com",
		"Content-Type":          "application/octet-stream",
	}))

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.True(t, strings.HasPrefix(recorder.Body.String(), peBody), "response starts with the input")
	assert.True(t, strings.HasSuffix(recorder.Body.String(), signer.FakeMarker), "response was signed")

	requests := fake.Requests()
	require.Len(t, requests, 1)
	assert.Equal(t, "Notifiarr", requests[0].Name)
	assert.Equal(t, "https://notifiarr.com", requests[0].URL)
	assert.True(t, strings.HasSuffix(requests[0].InputPath, ".exe"), "temp file keeps the .exe extension")
}

func TestSignLoopbackSkipsAuth(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	req := signRequest(t.Context(), peBody, nil)
	req.RemoteAddr = "127.0.0.1:9999"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	req = signRequest(t.Context(), peBody, nil)
	req.RemoteAddr = "[::1]:9999"

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
}

func TestSignAuthFailures(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{name: "no token"},
		{
			name:    "bad token",
			headers: map[string]string{"Authorization": "Bearer nope"},
		},
		{
			name:    "empty bearer",
			headers: map[string]string{"Authorization": "Bearer "},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, test.headers))
			assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		})
	}

	assert.Empty(t, fake.Requests(), "nothing may reach the signer without auth")
}

func TestSignNoVerifierFailsClosed(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := server.New(&server.Config{Signer: fake, WorkDir: t.TempDir()}).Handler()

	recorder := httptest.NewRecorder()
	authed := signRequest(t.Context(), peBody, map[string]string{"Authorization": "Bearer " + goodToken})
	handler.ServeHTTP(recorder, authed)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Empty(t, fake.Requests())
}

func TestSignRejectsBadMagic(t *testing.T) {
	t.Parallel()

	handler := newServer(t, &signer.Fake{})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), "#!/bin/sh\necho not windows\n", map[string]string{
		"Authorization": "Bearer " + goodToken,
	}))
	assert.Equal(t, http.StatusUnsupportedMediaType, recorder.Code)
}

func TestSignRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	handler := newServer(t, &signer.Fake{}) // MaxBody is 1024 in newServer.

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), "MZ"+strings.Repeat("x", 2048), map[string]string{
		"Authorization": "Bearer " + goodToken,
	}))
	assert.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
}

func TestSignBackendFailure(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	fake.SetSignErr(errors.New("pcscd lost the token"))
	handler := newServer(t, fake)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, map[string]string{
		"Authorization": "Bearer " + goodToken,
	}))
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "signing failed\n", recorder.Body.String(), "backend errors stay in the server log")
}

func TestSignMSIMagic(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	msi := string([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) + " fake msi"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), msi, map[string]string{
		"Authorization": "Bearer " + goodToken,
	}))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	requests := fake.Requests()
	require.Len(t, requests, 1)
	assert.True(t, strings.HasSuffix(requests[0].InputPath, ".msi"), "MSI uploads get a .msi temp file")
}

func TestSignSanitizesEvilFilename(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, map[string]string{
		"Authorization":         "Bearer " + goodToken,
		codesign.HeaderFilename: "../../../etc/passwd.EVIL~$",
	}))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	requests := fake.Requests()
	require.Len(t, requests, 1)
	assert.True(t, strings.HasSuffix(requests[0].InputPath, ".exe"),
		"weird extensions fall back to the magic-derived one, got %s", requests[0].InputPath)
	assert.NotContains(t, requests[0].InputPath, "..")
}

func TestSignExtensionMatchesMagic(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	handler := newServer(t, fake)

	msi := string([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) + " fake msi"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), msi, map[string]string{
		"Authorization":         "Bearer " + goodToken,
		codesign.HeaderFilename: "app.exe",
	}))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.True(t, strings.HasSuffix(fake.Requests()[0].InputPath, ".msi"),
		"MSI magic wins over a .exe filename")

	fake = &signer.Fake{}
	handler = newServer(t, fake)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, map[string]string{
		"Authorization":         "Bearer " + goodToken,
		codesign.HeaderFilename: "plugin.dll",
	}))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.True(t, strings.HasSuffix(fake.Requests()[0].InputPath, ".dll"),
		"PE-compatible extensions are preserved")
}

func TestServeAndShutdown(t *testing.T) {
	t.Parallel()

	daemon := server.New(&server.Config{
		Addr:    "127.0.0.1:0",
		Signer:  &signer.Fake{},
		WorkDir: t.TempDir(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() {
		done <- daemon.Serve(ctx)
	}()

	cancel()
	require.NoError(t, <-done)
}

func TestGetSignNotAllowed(t *testing.T) {
	t.Parallel()

	handler := newServer(t, &signer.Fake{})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, codesign.SignPath, bytes.NewReader(nil))
	req.RemoteAddr = remotePeer
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
}

func TestNewNilConfig(t *testing.T) {
	t.Parallel()

	require.NotNil(t, server.New(nil))
}

func TestSignRejectsBadMetadata(t *testing.T) {
	t.Parallel()

	tooLong := strings.Repeat("n", 257)

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "nul in name",
			headers: map[string]string{
				"Authorization":     "Bearer " + goodToken,
				codesign.HeaderName: "app\x00hidden",
			},
		},
		{
			name: "newline in url",
			headers: map[string]string{
				"Authorization":    "Bearer " + goodToken,
				codesign.HeaderURL: "https://example.com\nX-Injected: 1",
			},
		},
		{
			name: "too long",
			headers: map[string]string{
				"Authorization":     "Bearer " + goodToken,
				codesign.HeaderName: tooLong,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler := newServer(t, &signer.Fake{})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, test.headers))
			assert.Equal(t, http.StatusBadRequest, recorder.Code)
		})
	}
}

type blockingHealth struct {
	signer.Fake
}

func (b *blockingHealth) Health(ctx context.Context) error {
	<-ctx.Done()

	return fmt.Errorf("health blocked: %w", ctx.Err())
}

func TestHealthTimeout(t *testing.T) {
	t.Parallel()

	handler := server.New(&server.Config{
		Signer:        &blockingHealth{},
		Verifier:      stubVerifier{},
		WorkDir:       t.TempDir(),
		HealthTimeout: 50 * time.Millisecond,
	}).Handler()

	recorder := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, codesign.HealthPath, http.NoBody)
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Equal(t, "unhealthy\n", recorder.Body.String())
}

type holdingSign struct {
	signer.Fake

	started chan struct{}
	release chan struct{}
}

func (h *holdingSign) Sign(ctx context.Context, req *signer.Request) error {
	close(h.started)
	<-h.release

	err := h.Fake.Sign(ctx, req)
	if err != nil {
		return fmt.Errorf("holding sign: %w", err)
	}

	return nil
}

func TestHealthTimesOutWaitingForSign(t *testing.T) {
	t.Parallel()

	hold := &holdingSign{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	handler := server.New(&server.Config{
		Signer:        hold,
		Verifier:      stubVerifier{},
		WorkDir:       t.TempDir(),
		MaxBody:       1024,
		HealthTimeout: 50 * time.Millisecond,
	}).Handler()

	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, signRequest(t.Context(), peBody, map[string]string{
			"Authorization": "Bearer " + goodToken,
		}))
	}()

	<-hold.started

	recorder := httptest.NewRecorder()
	healthReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, codesign.HealthPath, http.NoBody)
	handler.ServeHTTP(recorder, healthReq)
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)

	close(hold.release)
}
