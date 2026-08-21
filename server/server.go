// Package server implements the signerd HTTP daemon: GET /health and
// POST /v1/sign. Every remote request must carry a valid GitHub Actions OIDC
// token; only connections from the daemon's own loopback interface skip that
// check (that is what SSH tunnels land on). Requests proxied by nginx or a
// Docker network are never loopback, so they always authenticate.
//
// Signing is serialized with a mutex because the hardware token performs one
// operation at a time.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golift.io/codesign"
	"golift.io/codesign/oidc"
	"golift.io/codesign/signer"
)

const (
	// DefaultAddr binds to loopback only. Publishing the daemon beyond
	// loopback without a proxy in front bypasses the mTLS gate; do not.
	DefaultAddr = "127.0.0.1:8750"
	// DefaultMaxBody caps uploads at 100 MiB.
	DefaultMaxBody = 100 << 20
	// shutdownWait bounds a graceful shutdown.
	shutdownWait = 10 * time.Second
	// readHeaderWait bounds reading request headers, mostly to satisfy
	// slow-loris concerns on a loopback bind.
	readHeaderWait = 10 * time.Second
)

var (
	// ErrNoVerifier rejects remote requests when no OIDC verifier is
	// configured. Loopback requests still work.
	ErrNoVerifier = errors.New("no OIDC verifier configured, remote signing is disabled")
	// ErrNoToken rejects remote requests without a bearer token.
	ErrNoToken = errors.New("missing Authorization bearer token")
	// errNotSignable rejects uploads that are not PE or MSI files.
	errNotSignable = errors.New("request body is not a PE or MSI file")
)

// Verifier validates a GitHub Actions OIDC bearer token. *oidc.Verifier
// implements it; tests inject stubs.
type Verifier interface {
	Verify(ctx context.Context, token string) (*oidc.Claims, error)
}

// Config assembles a Server.
type Config struct {
	// Addr is the listen address. Defaults to DefaultAddr. Keep the host
	// part on loopback unless a proxy enforces mTLS in front of the daemon.
	Addr string
	// MaxBody caps the request body in bytes. Defaults to DefaultMaxBody.
	MaxBody int64
	// Signer performs the actual signing. Required.
	Signer signer.Signer
	// Verifier checks GitHub OIDC tokens on remote requests. When nil,
	// every remote request is rejected and only loopback callers can sign.
	Verifier Verifier
	// WorkDir holds per-request temp files. Defaults to os.TempDir().
	WorkDir string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server is the signerd HTTP daemon. Create one with New.
type Server struct {
	config Config
	signMu sync.Mutex
	web    *http.Server
}

// New returns a Server with defaults applied.
func New(config *Config) *Server {
	server := &Server{config: *config}

	if server.config.Addr == "" {
		server.config.Addr = DefaultAddr
	}

	if server.config.MaxBody == 0 {
		server.config.MaxBody = DefaultMaxBody
	}

	if server.config.WorkDir == "" {
		server.config.WorkDir = os.TempDir()
	}

	if server.config.Logger == nil {
		server.config.Logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+codesign.HealthPath, server.handleHealth)
	mux.HandleFunc("POST "+codesign.SignPath, server.handleSign)

	server.web = &http.Server{
		Addr:              server.config.Addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderWait,
	}

	return server
}

// Handler exposes the HTTP handler for tests and embedding.
func (s *Server) Handler() http.Handler {
	return s.web.Handler
}

// Serve runs the daemon until the context is canceled, then shuts it down
// gracefully.
func (s *Server) Serve(ctx context.Context) error {
	errs := make(chan error, 1)

	go func() {
		errs <- s.web.ListenAndServe()
	}()

	s.config.Logger.Info("signerd listening", "addr", s.config.Addr)

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil // Normal close is not a failure.
		}

		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownWait)
	defer cancel()

	err := s.web.Shutdown(shutCtx)
	if err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}

	return nil
}

// handleHealth reports whether the backend can sign right now. It requires
// no authentication and never touches the PIN.
func (s *Server) handleHealth(resp http.ResponseWriter, req *http.Request) {
	err := s.config.Signer.Health(req.Context())
	if err != nil {
		s.config.Logger.Error("health check failed", "error", err)
		http.Error(resp, "unhealthy: "+err.Error(), http.StatusServiceUnavailable)

		return
	}

	_, _ = resp.Write([]byte("OK\n"))
}

// handleSign authenticates the caller, validates the upload, and returns the
// signed file.
func (s *Server) handleSign(resp http.ResponseWriter, req *http.Request) {
	start := time.Now()

	caller, err := s.authenticate(req)
	if err != nil {
		s.config.Logger.Warn("sign request rejected", "remote", req.RemoteAddr, "error", err)
		http.Error(resp, "unauthorized: "+err.Error(), http.StatusUnauthorized)

		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(resp, req.Body, s.config.MaxBody))
	if err != nil {
		status := http.StatusBadRequest

		maxBytesErr := &http.MaxBytesError{}
		if errors.As(err, &maxBytesErr) {
			status = http.StatusRequestEntityTooLarge
		}

		http.Error(resp, "reading request body: "+err.Error(), status)

		return
	}

	kind := fileKind(body)
	if kind == "" {
		http.Error(resp, errNotSignable.Error(), http.StatusUnsupportedMediaType)

		return
	}

	signed, err := s.sign(req, body, kind)
	if err != nil {
		s.config.Logger.Error("signing failed", "remote", req.RemoteAddr, "caller", caller, "error", err)
		http.Error(resp, "signing failed: "+err.Error(), http.StatusInternalServerError)

		return
	}

	s.config.Logger.Info("signed file",
		"remote", req.RemoteAddr,
		"caller", caller,
		"filename", req.Header.Get(codesign.HeaderFilename),
		"bytes", len(body),
		"elapsed", time.Since(start).Round(time.Millisecond))

	resp.Header().Set("Content-Type", "application/octet-stream")
	_, _ = resp.Write(signed)
}

// authenticate decides whether this request may sign. Loopback peers are
// trusted (SSH tunnels land here); everyone else needs a valid GitHub OIDC
// token whose repository is allowlisted. It returns a caller description for
// the log line.
func (s *Server) authenticate(req *http.Request) (string, error) {
	if isLoopback(req.RemoteAddr) {
		return "loopback", nil
	}

	token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return "", ErrNoToken
	}

	if s.config.Verifier == nil {
		return "", ErrNoVerifier
	}

	claims, err := s.config.Verifier.Verify(req.Context(), token)
	if err != nil {
		return "", fmt.Errorf("verifying OIDC token: %w", err)
	}

	return claims.Repository, nil
}

// sign writes the upload to a temp file, runs the backend under the signing
// mutex, and returns the signed bytes. Temp files keep a real extension
// because the tools pick their format from it.
func (s *Server) sign(req *http.Request, body []byte, kind string) ([]byte, error) {
	dir, err := os.MkdirTemp(s.config.WorkDir, "signerd-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	ext := safeExtension(req.Header.Get(codesign.HeaderFilename), kind)
	input := filepath.Join(dir, "input"+ext)
	output := filepath.Join(dir, "output"+ext)

	const onlyOwner = 0o600

	err = os.WriteFile(input, body, onlyOwner)
	if err != nil {
		return nil, fmt.Errorf("writing temp file: %w", err)
	}

	request := &signer.Request{
		InputPath:  input,
		OutputPath: output,
		Name:       req.Header.Get(codesign.HeaderName),
		URL:        req.Header.Get(codesign.HeaderURL),
	}

	err = s.signLocked(req.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("backend: %w", err)
	}

	signed, err := os.ReadFile(output)
	if err != nil {
		return nil, fmt.Errorf("reading signed file: %w", err)
	}

	return signed, nil
}

// signLocked serializes backend calls. The unlock is deferred so a panicking
// backend cannot leave the mutex held and deadlock every later request.
func (s *Server) signLocked(ctx context.Context, request *signer.Request) error {
	s.signMu.Lock()
	defer s.signMu.Unlock()

	//nolint:wrapcheck // The caller wraps with backend context.
	return s.config.Signer.Sign(ctx, request)
}

// isLoopback reports whether the peer address is 127.0.0.0/8 or ::1.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	addr := net.ParseIP(host)

	return addr != nil && addr.IsLoopback()
}

// fileKind returns a default file extension for the upload based on its
// magic bytes, or "" when the upload is not signable.
func fileKind(body []byte) string {
	if len(body) >= 2 && body[0] == 'M' && body[1] == 'Z' {
		return ".exe"
	}

	// The compound-file signature MSI packages start with.
	msiMagic := []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	if bytes.HasPrefix(body, msiMagic) {
		return ".msi"
	}

	return ""
}

// safeExtension returns the sanitized extension of the client-supplied file
// name, or the magic-derived fallback when the name is absent or weird. Only
// short, plain alphanumeric extensions are reused in temp file names.
func safeExtension(filename, fallback string) string {
	const maxExtension = 6 // dot plus up to five characters, .setup

	ext := strings.ToLower(filepath.Ext(filepath.Base(filename)))
	if len(ext) < 2 || len(ext) > maxExtension {
		return fallback
	}

	for _, char := range ext[1:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return fallback
		}
	}

	return ext
}
