// Package server implements the signerd HTTP daemon: GET /health and
// POST /v1/sign. Remote requests must carry a valid GitHub Actions OIDC
// token. Loopback peers skip that check only when
// AllowUnauthenticatedLoopback is set; the default is off so a reverse
// proxy aimed at a loopback upstream cannot bypass OIDC.
//
// Signing and token-touching health checks share a mutex because the
// hardware token performs one operation at a time. Unauthenticated
// /health results are cached briefly so probes cannot hammer the token.
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
	"strconv"
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
	// healthWait bounds GET /health, including waiting on an in-flight sign.
	// Unauthenticated probes must not hold the token mutex indefinitely.
	healthWait = 15 * time.Second
	// healthCacheTTL reuses a /health result so unauthenticated probes
	// cannot stampede the hardware token.
	healthCacheTTL = 5 * time.Second
	// maxMetadata is the longest Authenticode name or URL accepted from a
	// request header (and then passed as a single tool argument).
	maxMetadata = 256
)

var (
	// ErrNoVerifier rejects requests that need OIDC when no verifier is
	// configured. Loopback skip (when enabled) still works.
	ErrNoVerifier = errors.New("no OIDC verifier configured, remote signing is disabled")
	// ErrNoToken rejects remote requests without a bearer token.
	ErrNoToken = errors.New("missing Authorization bearer token")
	// errNotSignable rejects uploads that are not PE or MSI files.
	errNotSignable = errors.New("request body is not a PE or MSI file")
	// errBadMetadata rejects Authenticode name/URL headers that cannot be
	// passed safely to the signing tool.
	errBadMetadata = errors.New("authenticode name or url is invalid")
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
	// Verifier checks GitHub OIDC tokens. When nil, every request that
	// is not an opted-in loopback skip is rejected.
	Verifier Verifier
	// AllowUnauthenticatedLoopback, when true, lets peers on 127.0.0.0/8
	// and ::1 skip OIDC. Default false: v1 is GitHub Actions, and a reverse
	// proxy using a loopback upstream would otherwise skip the gate for every
	// client. Enable only for an SSH-tunnel operator workflow.
	AllowUnauthenticatedLoopback bool
	// WorkDir holds per-request temp files. Defaults to os.TempDir().
	WorkDir string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// HealthTimeout bounds GET /health, including waiting for the token
	// mutex. Defaults to 15s. Tests may set a shorter value.
	HealthTimeout time.Duration
	// HealthCacheTTL is how long a /health result is reused. Zero means
	// the default (5s). Negative disables the cache (tests).
	HealthCacheTTL time.Duration
}

// Server is the signerd HTTP daemon. Create one with New.
type Server struct {
	config    Config
	signMu    sync.Mutex
	uploads   chan struct{}
	web       *http.Server
	healthMu  sync.Mutex
	healthAt  time.Time
	healthErr error
}

// New returns a Server with defaults applied. A nil config gets pure defaults.
func New(config *Config) *Server {
	if config == nil {
		config = &Config{}
	}

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

	if server.config.HealthTimeout == 0 {
		server.config.HealthTimeout = healthWait
	}

	if server.config.HealthCacheTTL == 0 {
		server.config.HealthCacheTTL = healthCacheTTL
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
// this endpoint is unauthenticated. Results are cached briefly so a probe
// storm cannot occupy the token mutex.
func (s *Server) handleHealth(resp http.ResponseWriter, req *http.Request) {
	if hit, err := s.cachedHealth(); hit {
		writeHealth(resp, err)

		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), s.config.HealthTimeout)
	defer cancel()

	probed := false

	err := s.withToken(ctx, func(ctx context.Context) error {
		if hit, err := s.cachedHealth(); hit {
			return err
		}

		probed = true

		err := s.config.Signer.Health(ctx)
		if err != nil {
			err = fmt.Errorf("backend health: %w", err)
		}

		if ctx.Err() == nil {
			s.storeHealth(err)
		}

		return err
	})
	if probed && err != nil {
		s.config.Logger.Error("health check failed", "error", err)
	}

	writeHealth(resp, err)
}

func writeHealth(resp http.ResponseWriter, err error) {
	if err != nil {
		http.Error(resp, "unhealthy", http.StatusServiceUnavailable)

		return
	}

	_, _ = resp.Write([]byte("OK\n"))
}

func (s *Server) cachedHealth() (bool, error) {
	if s.config.HealthCacheTTL < 0 {
		return false, nil
	}

	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.healthAt.IsZero() || time.Since(s.healthAt) >= s.config.HealthCacheTTL {
		return false, nil
	}

	return true, s.healthErr
}

func (s *Server) storeHealth(err error) {
	if s.config.HealthCacheTTL < 0 {
		return
	}

	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	s.healthAt = time.Now()
	s.healthErr = err
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

	size, err := s.signUpload(resp, req)
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
	case errors.Is(err, errBadMetadata):
		status = http.StatusBadRequest
		message = errBadMetadata.Error()
	default:
		s.config.Logger.Error("signing failed", "remote", req.RemoteAddr, "caller", caller, "error", err)
	}

	if status != http.StatusInternalServerError {
		s.config.Logger.Warn("sign request rejected",
			"remote", req.RemoteAddr, "caller", caller, "error", err)
	}

	http.Error(resp, message, status)
}

// authenticate decides whether this request may sign. Loopback peers skip
// OIDC only when AllowUnauthenticatedLoopback is set; everyone else needs a
// valid GitHub OIDC token whose repository is allowlisted. It returns a
// caller description for the log line.
func (s *Server) authenticate(req *http.Request) (string, error) {
	if s.config.AllowUnauthenticatedLoopback && isLoopback(req.RemoteAddr) {
		return "loopback", nil
	}

	token, ok := bearerToken(req.Header.Get("Authorization"))
	if !ok {
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

// bearerToken extracts a Bearer token. RFC 7235 treats the scheme as
// case-insensitive, so "Bearer" and "bearer" both work.
func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}

	return token, true
}

// signUpload streams the body to a temp file, checks PE/MSI magic, runs the
// backend under the token mutex, and copies the signed file to the response.
func (s *Server) signUpload(resp http.ResponseWriter, req *http.Request) (int64, error) {
	dir, err := os.MkdirTemp(s.config.WorkDir, "signerd-*")
	if err != nil {
		return 0, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	upload := filepath.Join(dir, "upload")

	file, err := os.OpenFile(upload, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:mnd
	if err != nil {
		return 0, fmt.Errorf("creating upload file: %w", err)
	}

	size, err := io.Copy(file, http.MaxBytesReader(resp, req.Body, s.config.MaxBody))
	if err != nil {
		_ = file.Close()

		return 0, fmt.Errorf("reading request body: %w", err)
	}

	kind, err := detectKind(file)
	_ = file.Close()

	if err != nil {
		return 0, err
	}

	ext := safeExtension(req.Header.Get(codesign.HeaderFilename), kind)
	input := filepath.Join(dir, "input"+ext)
	output := filepath.Join(dir, "output"+ext)

	err = os.Rename(upload, input)
	if err != nil {
		return 0, fmt.Errorf("naming temp file: %w", err)
	}

	request, err := signingRequest(input, output, req)
	if err != nil {
		return 0, err
	}

	err = s.withToken(req.Context(), func(ctx context.Context) error {
		return s.config.Signer.Sign(ctx, request)
	})
	if err != nil {
		return 0, fmt.Errorf("backend: %w", err)
	}

	err = writeSigned(resp, output)
	if err != nil {
		return 0, err
	}

	return size, nil
}

func signingRequest(input, output string, req *http.Request) (*signer.Request, error) {
	name, err := sanitizeMetadata(req.Header.Get(codesign.HeaderName))
	if err != nil {
		return nil, err
	}

	page, err := sanitizeMetadata(req.Header.Get(codesign.HeaderURL))
	if err != nil {
		return nil, err
	}

	return &signer.Request{
		InputPath:  input,
		OutputPath: output,
		Name:       name,
		URL:        page,
	}, nil
}

func writeSigned(resp http.ResponseWriter, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening signed file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("statting signed file: %w", err)
	}

	resp.Header().Set("Content-Type", "application/octet-stream")
	resp.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))

	_, err = io.Copy(resp, file)
	if err != nil {
		return fmt.Errorf("writing signed file: %w", err)
	}

	return nil
}

// withToken serializes hardware-token operations (sign and health). The lock
// wait respects ctx so a timed-out health probe cannot sit behind a sign
// forever. Unlock is deferred so a panicking backend cannot deadlock the daemon.
func (s *Server) withToken(ctx context.Context, operation func(context.Context) error) error {
	acquired := make(chan struct{})

	go func() {
		s.signMu.Lock()

		select {
		case acquired <- struct{}{}:
		case <-ctx.Done():
			s.signMu.Unlock()
		}
	}()

	select {
	case <-acquired:
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
	case <-ctx.Done():
		return fmt.Errorf("token operation canceled: %w", ctx.Err())
	}
}

// sanitizeMetadata trims Authenticode name/URL headers and rejects values
// that are unsafe to pass as a signing-tool argument.
func sanitizeMetadata(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	if len(value) > maxMetadata || strings.ContainsAny(value, "\x00\r\n") {
		return "", errBadMetadata
	}

	return value, nil
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
