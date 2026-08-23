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
	"encoding/binary"
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
	token     chan struct{}
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
		token:   make(chan struct{}, 1),
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

// withToken serializes hardware-token operations (sign and health) through a
// one-slot semaphore. Acquisition is a context-aware channel send, so a
// canceled or timed-out caller (for example an unauthenticated /health probe)
// returns at once instead of leaking a goroutine parked on a mutex while a slow
// sign holds the token. A panicking backend releases the slot via defer.
func (s *Server) withToken(ctx context.Context, operation func(context.Context) error) error {
	select {
	case s.token <- struct{}{}:
		defer func() { <-s.token }()
	case <-ctx.Done():
		return fmt.Errorf("token operation canceled: %w", ctx.Err())
	}

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

// detectKind classifies an uploaded file by inspecting its header and returns
// the temp-file extension the backend should use. It is a coarse gate; the
// backend performs authoritative format validation. A PE must carry the
// "PE\0\0" signature (not merely "MZ"), and a compound file must carry a
// Windows Installer class id, so DOS stubs and Office documents are rejected
// with 415 instead of reaching the signer.
func detectKind(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("statting upload: %w", err)
	}

	switch {
	case isPE(file, info.Size()):
		return ".exe", nil
	case isMSI(file, info.Size()):
		return ".msi", nil
	default:
		return "", errNotSignable
	}
}

// isPE reports whether the file is a PE image: an "MZ" DOS header whose
// e_lfanew offset points at the "PE\0\0" signature.
func isPE(file io.ReaderAt, size int64) bool {
	const (
		dosHeaderLen = 0x40 // through e_lfanew (uint32 at 0x3C)
		lfanewAt     = 0x3C
		peSigLen     = 4
	)

	if size < dosHeaderLen {
		return false
	}

	dos := make([]byte, dosHeaderLen)

	_, err := file.ReadAt(dos, 0)
	if err != nil {
		return false
	}

	if dos[0] != 'M' || dos[1] != 'Z' {
		return false
	}

	lfanew := int64(binary.LittleEndian.Uint32(dos[lfanewAt:]))

	sig := make([]byte, peSigLen)

	_, err = file.ReadAt(sig, lfanew)
	if err != nil {
		return false
	}

	return bytes.Equal(sig, []byte("PE\x00\x00"))
}

// cfbfMagic is the Compound File Binary Format (OLE) signature shared by MSI
// packages and other compound documents such as legacy Office files.
const cfbfMagic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

// isMSI reports whether a compound-file upload is a Windows Installer package
// by reading its root storage class id. It fails open: a compound file whose
// class id cannot be read with confidence (short, unusual sector size) is
// treated as an MSI and left for the backend to validate, so a valid installer
// is never rejected here. Non-compound files, and compound files with a
// non-installer class id (Office documents), return false.
func isMSI(file io.ReaderAt, size int64) bool {
	sig := make([]byte, len(cfbfMagic))

	_, err := file.ReadAt(sig, 0)
	if err != nil || string(sig) != cfbfMagic {
		return false
	}

	clsid, ok := compoundRootCLSID(file, size)
	if !ok {
		return true
	}

	return isInstallerCLSID(clsid)
}

// compoundRootCLSID returns the 16-byte class id of a compound file's root
// storage entry, or ok=false when the header or directory cannot be located.
func compoundRootCLSID(file io.ReaderAt, size int64) ([]byte, bool) {
	const (
		headerLen        = 512
		sectorShiftAt    = 30
		firstDirSectorAt = 48
		dirEntryLen      = 128
		rootCLSIDAt      = 0x50
		clsidLen         = 16
		minSectorShift   = 7  // 128-byte sectors
		maxSectorShift   = 12 // 4096-byte sectors
		freeSector       = 0xFFFFFFFF
	)

	if size < headerLen {
		return nil, false
	}

	header := make([]byte, headerLen)

	_, err := file.ReadAt(header, 0)
	if err != nil {
		return nil, false
	}

	sectorShift := binary.LittleEndian.Uint16(header[sectorShiftAt:])
	if sectorShift < minSectorShift || sectorShift > maxSectorShift {
		return nil, false
	}

	firstDirSector := binary.LittleEndian.Uint32(header[firstDirSectorAt:])
	if firstDirSector == freeSector {
		return nil, false
	}

	dirOffset := (int64(firstDirSector) + 1) * (int64(1) << sectorShift)
	if dirOffset+dirEntryLen > size {
		return nil, false
	}

	entry := make([]byte, dirEntryLen)

	_, err = file.ReadAt(entry, dirOffset)
	if err != nil {
		return nil, false
	}

	return entry[rootCLSIDAt : rootCLSIDAt+clsidLen], true
}

// isInstallerCLSID reports whether a compound-file root class id belongs to the
// Windows Installer family, all sharing the -0000-0000-C000-000000000046 tail.
func isInstallerCLSID(clsid []byte) bool {
	const (
		clsidLen = 16
		msi      = 0x000C1084 // .msi database
		msp      = 0x000C1086 // .msp patch
		mst      = 0x000C1082 // .mst transform
		msm      = 0x000C1090 // .msm merge module
	)

	if len(clsid) != clsidLen {
		return false
	}

	switch binary.LittleEndian.Uint32(clsid[0:4]) {
	case msi, msp, mst, msm:
	default:
		return false
	}

	tail := []byte{0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

	return bytes.Equal(clsid[4:16], tail)
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
