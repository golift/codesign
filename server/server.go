// Package server implements the signerd HTTP daemon: GET /health and
// POST /v1/sign. Every remote request must carry a valid GitHub Actions OIDC
// token; only connections from the daemon's own loopback interface skip that
// check (that is what SSH tunnels land on). Requests proxied by nginx or a
// Docker network are never loopback, so they always authenticate.
//
// Signing and token-touching health checks share a mutex because the
// hardware token performs one operation at a time.
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
	// readHeaderWait bounds reading request headers (slow-loris).
	readHeaderWait = 10 * time.Second
	// bodyWait bounds reading a full upload and writing the signed result.
	// Sized for DefaultMaxBody over a modest link plus the timestamp round trip.
	bodyWait = 5 * time.Minute
	// maxInFlightUploads caps concurrent body reads. Only one request signs
	// at a time; extras would otherwise each retain up to MaxBody on disk
	// (and previously in memory) while waiting on the token.
	maxInFlightUploads = 2
)

var (
	// ErrNoVerifier rejects remote requests when no OIDC verifier is
	// configured. Loopback requests still work.
	ErrNoVerifier = errors.New("no OIDC verifier configured, remote signing is disabled")
	// ErrNoToken rejects remote requests without a bearer token.
	ErrNoToken = errors.New("missing Authorization bearer token")
	// errNotSignable rejects uploads that are not PE or MSI files.
	errNotSignable = errors.New("request body is not a PE or MSI file")
	// errBusy rejects a sign request when too many uploads are already in flight.
	errBusy = errors.New("too many signing requests in flight")
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
	config  Config
	signMu  sync.Mutex
	uploads chan struct{}
	web     *http.Server
}

// New returns a Server with defaults applied.
func New(config *Config) *Server {
	server := &Server{
		config:  *config,
		uploads: make(chan struct{}, maxInFlightUploads),
	}

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
		ReadTimeout:       bodyWait,
		WriteTimeout:      bodyWait,
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
// no authentication and never touches the PIN. Details stay in the log:
// this endpoint is unauthenticated.
func (s *Server) handleHealth(resp http.ResponseWriter, req *http.Request) {
	err := s.withToken(req.Context(), func(ctx context.Context) error {
		return s.config.Signer.Health(ctx)
	})
	if err != nil {
		s.config.Logger.Error("health check failed", "error", err)
		http.Error(resp, "unhealthy", http.StatusServiceUnavailable)

		return
	}

	_, _ = resp.Write([]byte("OK\n"))
}

// handleSign authenticates the caller, streams the upload to disk, and
// returns the signed file.
func (s *Server) handleSign(resp http.ResponseWriter, req *http.Request) {
	start := time.Now()

	caller, err := s.authenticate(req)
	if err != nil {
		s.config.Logger.Warn("sign request rejected", "remote", req.RemoteAddr, "error", err)
		http.Error(resp, "unauthorized", http.StatusUnauthorized)

		return
	}

	select {
	case s.uploads <- struct{}{}:
		defer func() { <-s.uploads }()
	default:
		http.Error(resp, "too many signing requests", http.StatusServiceUnavailable)

		return
	}

	filename := req.Header.Get(codesign.HeaderFilename)

	signed, size, err := s.signUpload(resp, req)
	if err != nil {
		s.replySignError(resp, req, caller, err)

		return
	}

	s.config.Logger.Info("signed file",
		"remote", req.RemoteAddr,
		"caller", caller,
		"filename", filename,
		"bytes", size,
		"elapsed", time.Since(start).Round(time.Millisecond))

	resp.Header().Set("Content-Type", "application/octet-stream")
	_, _ = resp.Write(signed)
}

// replySignError maps a signing failure to an HTTP status without leaking
// backend or token diagnostics to the caller.
func (s *Server) replySignError(resp http.ResponseWriter, req *http.Request, caller string, err error) {
	status := http.StatusInternalServerError
	message := "signing failed"

	switch {
	case errors.Is(err, errNotSignable):
		status = http.StatusUnsupportedMediaType
		message = errNotSignable.Error()
	case errors.As(err, new(*http.MaxBytesError)):
		status = http.StatusRequestEntityTooLarge
		message = "request body too large"
	case errors.Is(err, errBusy):
		status = http.StatusServiceUnavailable
		message = errBusy.Error()
	default:
		s.config.Logger.Error("signing failed", "remote", req.RemoteAddr, "caller", caller, "error", err)
	}

	if status != http.StatusInternalServerError {
		s.config.Logger.Warn("sign request rejected",
			"remote", req.RemoteAddr, "caller", caller, "error", err)
	}

	http.Error(resp, message, status)
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

// signUpload streams the body to a temp file, checks PE/MSI magic, runs the
// backend under the token mutex, and returns the signed bytes.
func (s *Server) signUpload(resp http.ResponseWriter, req *http.Request) ([]byte, int64, error) {
	dir, err := os.MkdirTemp(s.config.WorkDir, "signerd-*")
	if err != nil {
		return nil, 0, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	upload := filepath.Join(dir, "upload")

	file, err := os.OpenFile(upload, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:mnd
	if err != nil {
		return nil, 0, fmt.Errorf("creating upload file: %w", err)
	}

	size, err := io.Copy(file, http.MaxBytesReader(resp, req.Body, s.config.MaxBody))
	if err != nil {
		_ = file.Close()

		return nil, 0, fmt.Errorf("reading request body: %w", err)
	}

	kind, err := detectKind(file)
	_ = file.Close()

	if err != nil {
		return nil, 0, err
	}

	ext := safeExtension(req.Header.Get(codesign.HeaderFilename), kind)
	input := filepath.Join(dir, "input"+ext)
	output := filepath.Join(dir, "output"+ext)

	err = os.Rename(upload, input)
	if err != nil {
		return nil, 0, fmt.Errorf("naming temp file: %w", err)
	}

	request := &signer.Request{
		InputPath:  input,
		OutputPath: output,
		Name:       req.Header.Get(codesign.HeaderName),
		URL:        req.Header.Get(codesign.HeaderURL),
	}

	err = s.withToken(req.Context(), func(ctx context.Context) error {
		return s.config.Signer.Sign(ctx, request)
	})
	if err != nil {
		return nil, 0, fmt.Errorf("backend: %w", err)
	}

	signed, err := os.ReadFile(output)
	if err != nil {
		return nil, 0, fmt.Errorf("reading signed file: %w", err)
	}

	return signed, size, nil
}

// withToken serializes hardware-token operations (sign and health). The
// unlock is deferred so a panicking backend cannot deadlock the daemon.
func (s *Server) withToken(ctx context.Context, operation func(context.Context) error) error {
	s.signMu.Lock()
	defer s.signMu.Unlock()

	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("token operation canceled: %w", err)
	}

	err = operation(ctx)
	if err != nil {
		return err
	}

	return nil
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

// detectKind reads magic bytes from the start of an uploaded file.
func detectKind(file *os.File) (string, error) {
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("rewinding upload: %w", err)
	}

	peek := make([]byte, 8) //nolint:mnd // PE is 2 bytes, MSI is 8.

	n, err := io.ReadFull(file, peek)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading magic: %w", err)
	}

	kind := fileKind(peek[:n])
	if kind == "" {
		return "", errNotSignable
	}

	return kind, nil
}

// fileKind returns a default file extension for the upload based on its
// magic bytes, or "" when the upload is not signable.
func fileKind(body []byte) string {
	if len(body) >= 2 && body[0] == 'M' && body[1] == 'Z' {
		return ".exe"
	}

	msiMagic := []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	if bytes.HasPrefix(body, msiMagic) {
		return ".msi"
	}

	return ""
}

// safeExtension returns a temp-file extension compatible with the
// magic-derived kind. A PE named ".msi" (or an MSI named ".exe") would make
// osslsigncode/jsign parse the file as the wrong format.
func safeExtension(filename, kind string) string {
	ext := sanitizedExt(filename)
	if !compatibleExt(ext, kind) {
		return kind
	}

	return ext
}

func sanitizedExt(filename string) string {
	const maxExtension = 6 // dot plus up to five characters, .setup

	ext := strings.ToLower(filepath.Ext(filepath.Base(filename)))
	if len(ext) < 2 || len(ext) > maxExtension {
		return ""
	}

	for _, char := range ext[1:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return ""
		}
	}

	return ext
}

func compatibleExt(ext, kind string) bool {
	switch kind {
	case ".exe":
		switch ext {
		case ".exe", ".dll", ".sys", ".efi", ".ocx", ".cpl":
			return true
		}
	case ".msi":
		return ext == ".msi"
	}

	return false
}
