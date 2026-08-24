// signerd is the daemon half of golift.io/codesign. It sits next to the
// hardware token (YubiKey PIV), listens on loopback (or a Docker network
// behind an mTLS-terminating proxy), and Authenticode-signs PE/MSI files
// POSTed to /v1/sign. Remote callers must present a GitHub Actions OIDC
// token from an allowlisted repository.
//
// Configuration comes from a TOML file, overridden by SIGNERD_* environment
// variables. See the example config and deploy files in the repository.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golift.io/cnfg"
	"golift.io/cnfgfile"
	"golift.io/codesign/backends"
	"golift.io/codesign/oidc"
	"golift.io/codesign/server"
	"golift.io/codesign/signer"
	"golift.io/version"
)

// Config is everything signerd reads from its config file. Any value may be
// overridden with an environment variable: SIGNERD_LISTEN, SIGNERD_PIN,
// SIGNERD_GITHUB_AUDIENCE, and so on.
type Config struct {
	// Listen is the daemon bind address. Keep the host part on loopback or a
	// container network; never publish it raw to a LAN or the internet.
	Listen string `toml:"listen" xml:"listen"`
	// MaxBodyMiB caps uploads, in MiB.
	MaxBodyMiB int64 `toml:"max_body_mib" xml:"max_body_mib"`
	// Backend picks the signing tool: osslsigncode (default), jsign, or
	// fake (testing only; appends a marker instead of signing).
	Backend string `toml:"backend" xml:"backend"`
	// Command overrides the backend binary path.
	Command string `toml:"command" xml:"command"`
	// PKCS11Module is the libykcs11 path for the osslsigncode backend.
	PKCS11Module string `toml:"pkcs11_module" xml:"pkcs11_module"`
	// CertFile is the PEM certificate chain for the signing key.
	CertFile string `toml:"cert_file" xml:"cert_file"`
	// KeyID is the osslsigncode -key value. Empty defaults to PIV slot 9A
	// (pkcs11:id=%01). osslsigncode requires -key even with a single token key.
	KeyID string `toml:"key_id" xml:"key_id"`
	// Alias selects the certificate for the jsign backend.
	Alias string `toml:"alias" xml:"alias"`
	// PIN is the token user PIN. Prefer SIGNERD_PIN or pin_file over
	// writing it in the config file. Never the PUK.
	PIN string `toml:"pin" xml:"pin"`
	// PINFile is a file holding the PIN, for Docker secrets.
	PINFile string `toml:"pin_file" xml:"pin_file"`
	// TimestampURL overrides the RFC 3161 timestamp authority.
	TimestampURL string `toml:"timestamp_url" xml:"timestamp_url"`
	// HealthCommand is the full health-check command (program + args) run
	// by GET /health. The default is a PIN-free pkcs11-tool probe that fails
	// when the token is unplugged. Override to target a specific slot or
	// certificate. Never needs the PIN.
	HealthCommand []string `toml:"health_command" xml:"health_command"`
	// Digest overrides the digest algorithm (default matches ECC P-384).
	Digest string `toml:"digest" xml:"digest"`
	// Name is the default Authenticode program name.
	Name string `toml:"name" xml:"name"`
	// URL is the default Authenticode program URL.
	URL string `toml:"url" xml:"url"`
	// WorkDir holds per-request temp files.
	WorkDir string `toml:"work_dir" xml:"work_dir"`
	// AllowUnauthenticatedLoopback lets 127.0.0.1/::1 skip OIDC. Default
	// false: v1 is GitHub Actions, and a reverse proxy aimed at a loopback
	// upstream would otherwise skip the gate. Enable only for an SSH-tunnel
	// operator workflow; any local process can then sign.
	AllowUnauthenticatedLoopback bool `toml:"allow_unauthenticated_loopback" xml:"allow_unauthenticated_loopback"`
	// Github configures OIDC verification for remote callers.
	Github GithubConfig `toml:"github" xml:"github"`
}

// GithubConfig is the [github] section: the OIDC gate for remote signing.
type GithubConfig struct {
	// Issuer defaults to GitHub's public Actions issuer.
	Issuer string `toml:"issuer" xml:"issuer"`
	// Audience must match the aud the caller requested, conventionally the
	// public signing URL.
	Audience string `toml:"audience" xml:"audience"`
	// AllowedRepositories lists Owner/repo values that may sign. Empty
	// means remote signing is disabled entirely.
	AllowedRepositories []string `toml:"allowed_repositories" xml:"allowed_repositories"`
}

func main() {
	err := run()
	if err != nil {
		slog.Error("signerd failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configFlag := flag.String("config", "", "path to signerd.toml (default: user config dir, then /etc/signerd)")
	versionFlag := flag.Bool("version", false, "print the version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Println(version.Print("signerd"))

		return nil
	}

	config, err := loadConfig(*configFlag)
	if err != nil {
		return err
	}

	err = validateConfig(config)
	if err != nil {
		return err
	}

	daemon, err := newDaemon(config)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = daemon.Serve(ctx)
	if err != nil {
		return fmt.Errorf("running daemon: %w", err)
	}

	return nil
}

func newDaemon(config *Config) (*server.Server, error) {
	backend, err := buildSigner(config)
	if err != nil {
		return nil, err
	}

	var verifier server.Verifier
	if len(config.Github.AllowedRepositories) > 0 {
		verifier = oidc.New(&oidc.Config{
			Issuer:              config.Github.Issuer,
			Audience:            config.Github.Audience,
			AllowedRepositories: config.Github.AllowedRepositories,
		})
	} else {
		slog.Warn("no allowed_repositories configured; remote signing is disabled")
	}

	if config.AllowUnauthenticatedLoopback {
		slog.Warn("allow_unauthenticated_loopback is on; any process that can reach loopback can sign")
	}

	return server.New(&server.Config{
		Addr:                         config.Listen,
		MaxBody:                      config.MaxBodyMiB * bytesPerMiB,
		Signer:                       backend,
		Verifier:                     verifier,
		WorkDir:                      config.WorkDir,
		AllowUnauthenticatedLoopback: config.AllowUnauthenticatedLoopback,
	}), nil
}

// loadConfig reads the config file (when present), then applies SIGNERD_*
// environment variables on top.
func loadConfig(path string) (*Config, error) {
	const defaultMaxBodyMiB = 100

	config := &Config{MaxBodyMiB: defaultMaxBodyMiB}

	if path == "" {
		path = findConfigFile()
	}

	if path != "" {
		err := cnfgfile.Unmarshal(config, path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	_, err := cnfg.UnmarshalENV(config, "SIGNERD")
	if err != nil {
		return nil, fmt.Errorf("parsing environment: %w", err)
	}

	if config.PIN == "" && config.PINFile != "" {
		pin, err := os.ReadFile(config.PINFile)
		if err != nil {
			return nil, fmt.Errorf("reading pin file: %w", err)
		}

		config.PIN = strings.TrimSpace(string(pin))
	}

	return config, nil
}

// findConfigFile returns the first config file that exists in the default
// locations, or "" when none do (environment-only configuration).
func findConfigFile() string {
	candidates := []string{"/etc/signerd/signerd.toml"}

	dir, err := os.UserConfigDir()
	if err == nil {
		candidates = append([]string{filepath.Join(dir, "signerd", "signerd.toml")}, candidates...)
	}

	for _, candidate := range candidates {
		_, err = os.Stat(candidate)
		// Anything but not-exist counts as a hit (permission problems, for
		// example) so loadConfig surfaces a clear error instead of silently
		// running on environment-only configuration.
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}

	return ""
}

// errUnknownBackend rejects a backend name that is not compiled in.
var (
	errUnknownBackend = errors.New("unknown backend, want osslsigncode, jsign, or fake")
	errNoPKCS11Module = errors.New("pkcs11_module is required")
	errNoCertFile     = errors.New("cert_file is required")
	errNoJsignProbe   = errors.New("jsign backend needs pkcs11_module or health_command")
	errFakeDisabled   = errors.New("fake backend requires SIGNERD_ALLOW_FAKE=1")
	errBadMaxBody     = errors.New("max_body_mib must be non-negative and not overflow int64 bytes")
	errNoAudience     = errors.New("github.audience is required when allowed_repositories is set")
	errNotRegularFile = errors.New("path is not a regular file")
)

const (
	allowFakeEnv = "SIGNERD_ALLOW_FAKE"
	bytesPerMiB  = 1 << 20
)

func requireFile(path, field string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", field, path, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s: %w", field, path, errNotRegularFile)
	}

	return nil
}

// validateConfig fails closed before the daemon listens: signing backends
// need their module and certificate chain on disk. The PIN is optional at
// start (health must not need it) but missing PIN is logged.
func validateConfig(config *Config) error {
	err := validateLimits(config)
	if err != nil {
		return err
	}

	if config.PIN == "" && !strings.EqualFold(config.Backend, "fake") {
		slog.Warn("no PIN configured; signing will fail until SIGNERD_PIN or pin_file is set")
	}

	switch strings.ToLower(config.Backend) {
	case "", "osslsigncode":
		return validateOSSL(config)
	case "jsign":
		return validateJsign(config)
	case "fake":
		return validateFake()
	default:
		return fmt.Errorf("%w: %s", errUnknownBackend, config.Backend)
	}
}

func validateLimits(config *Config) error {
	// Zero means "use the server default"; negative or overflowing values would
	// otherwise become a broken byte limit that rejects every upload.
	if config.MaxBodyMiB < 0 || config.MaxBodyMiB > math.MaxInt64/bytesPerMiB {
		return fmt.Errorf("%w: %d", errBadMaxBody, config.MaxBodyMiB)
	}

	// A nonempty allowlist enables remote signing. oidc.Verify then refuses
	// every token when audience is empty, while /health can still be healthy.
	// Fail here so the operator sees the misconfiguration at start.
	if len(config.Github.AllowedRepositories) > 0 && strings.TrimSpace(config.Github.Audience) == "" {
		return errNoAudience
	}

	return nil
}

func validateOSSL(config *Config) error {
	if config.PKCS11Module == "" {
		return errNoPKCS11Module
	}

	err := requireFile(config.PKCS11Module, "pkcs11_module")
	if err != nil {
		return err
	}

	if config.CertFile == "" {
		return errNoCertFile
	}

	return requireFile(config.CertFile, "cert_file")
}

func validateJsign(config *Config) error {
	if config.CertFile == "" {
		return errNoCertFile
	}

	err := requireFile(config.CertFile, "cert_file")
	if err != nil {
		return err
	}

	if config.PKCS11Module == "" && len(config.HealthCommand) == 0 {
		return errNoJsignProbe
	}

	if config.PKCS11Module != "" {
		return requireFile(config.PKCS11Module, "pkcs11_module")
	}

	return nil
}

func validateFake() error {
	if os.Getenv(allowFakeEnv) != "1" {
		return errFakeDisabled
	}

	return nil
}

// buildSigner turns the configuration into a signing backend.
func buildSigner(config *Config) (signer.Signer, error) { //nolint:ireturn // Picking a backend at runtime is the point.
	switch strings.ToLower(config.Backend) {
	case "", "osslsigncode":
		return backends.NewOSSLSigncode(&backends.OSSLConfig{
			Command:       config.Command,
			PKCS11Module:  config.PKCS11Module,
			CertFile:      config.CertFile,
			KeyID:         config.KeyID,
			PIN:           config.PIN,
			TimestampURL:  config.TimestampURL,
			Digest:        config.Digest,
			Name:          config.Name,
			URL:           config.URL,
			HealthCommand: config.HealthCommand,
		}), nil
	case "jsign":
		return backends.NewJsign(&backends.JsignConfig{
			Command:       config.Command,
			Alias:         config.Alias,
			CertFile:      config.CertFile,
			PIN:           config.PIN,
			TimestampURL:  config.TimestampURL,
			Digest:        config.Digest,
			Name:          config.Name,
			URL:           config.URL,
			PKCS11Module:  config.PKCS11Module,
			HealthCommand: config.HealthCommand,
		}), nil
	case "fake":
		if os.Getenv(allowFakeEnv) != "1" {
			return nil, errFakeDisabled
		}

		slog.Warn("using the FAKE signing backend; output files are not really signed")

		return &signer.Fake{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnknownBackend, config.Backend)
	}
}
