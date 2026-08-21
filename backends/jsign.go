package backends

import (
	"context"
	"fmt"
	"slices"

	"golift.io/codesign/signer"
)

// JsignConfig configures the jsign backend.
type JsignConfig struct {
	// Command is the jsign launcher. Defaults to "jsign".
	Command string
	// StoreType defaults to YUBIKEY, jsign's native PC/SC YubiKey store.
	StoreType string
	// Alias selects the certificate on the token, for example
	// "X.509 Certificate for PIV Authentication" for slot 9A.
	Alias string
	// CertFile is the PEM file holding the full code-signing certificate
	// chain, so the signature carries the intermediates.
	CertFile string
	// PIN is the token user PIN. It is written to a 0600 temp file and
	// passed as --storepass file:<path> so it never appears in process argv.
	// Never the PUK.
	PIN string
	// TimestampURL defaults to DefaultTimestampURL.
	TimestampURL string
	// Digest defaults to SHA-384 to match an ECC P-384 signing key.
	Digest string
	// Name is the default Authenticode program name.
	Name string
	// URL is the default Authenticode program URL.
	URL string
	// PKCS11Module is optional; when set, the default health check lists
	// certificates on this module. jsign itself uses StoreType, not this.
	PKCS11Module string
	// HealthCommand is the full health-check command (program + args).
	// The default is a PIN-free pkcs11-tool probe that fails when the
	// token is unplugged. It must never need the PIN.
	HealthCommand []string
	// Run defaults to Exec.
	Run Runner
}

// Jsign signs PE and MSI files by invoking jsign with its YubiKey key store.
// jsign signs in place, so the input is copied to the output path first and
// jsign runs against the copy. It implements signer.Signer.
type Jsign struct {
	config JsignConfig
}

// NewJsign returns a jsign backend with defaults applied. A nil config gets
// pure defaults.
func NewJsign(config *JsignConfig) *Jsign {
	if config == nil {
		config = &JsignConfig{}
	}

	backend := &Jsign{config: *config}

	if backend.config.Command == "" {
		backend.config.Command = "jsign"
	}

	if backend.config.StoreType == "" {
		backend.config.StoreType = "YUBIKEY"
	}

	if backend.config.TimestampURL == "" {
		backend.config.TimestampURL = DefaultTimestampURL
	}

	if backend.config.Digest == "" {
		backend.config.Digest = "SHA-384"
	}

	if len(backend.config.HealthCommand) == 0 {
		backend.config.HealthCommand = defaultTokenHealth(backend.config.PKCS11Module)
	}

	if backend.config.Run == nil {
		backend.config.Run = Exec
	}

	return backend
}

// Sign copies the input to the output path, then invokes jsign on the copy.
func (s *Jsign) Sign(ctx context.Context, req *signer.Request) error {
	err := signer.Check(req)
	if err != nil {
		return fmt.Errorf("jsign sign: %w", err)
	}

	err = copyFile(req.InputPath, req.OutputPath)
	if err != nil {
		return fmt.Errorf("jsign sign: %w", err)
	}

	args := []string{
		"--storetype", s.config.StoreType,
		"--certfile", s.config.CertFile,
		"--alg", s.config.Digest,
		"--tsaurl", s.config.TimestampURL,
	}

	return withPINFile(s.config.PIN, func(pinPath string) error {
		runArgs := slices.Clone(args)

		if s.config.Alias != "" {
			runArgs = append(runArgs, "--alias", s.config.Alias)
		}

		if pinPath != "" {
			runArgs = append(runArgs, "--storepass", "file:"+pinPath)
		}

		if name := fallback(req.Name, s.config.Name); name != "" {
			runArgs = append(runArgs, "--name", name)
		}

		if url := fallback(req.URL, s.config.URL); url != "" {
			runArgs = append(runArgs, "--url", url)
		}

		runArgs = append(runArgs, req.OutputPath)

		_, err := s.config.Run(ctx, s.config.Command, runArgs...)
		if err != nil {
			return fmt.Errorf("jsign sign: %w", err)
		}

		return nil
	})
}

// Health proves the signing tool is runnable and the token is present.
func (s *Jsign) Health(ctx context.Context) error {
	_, err := s.config.Run(ctx, s.config.Command, "--help")
	if err != nil {
		return fmt.Errorf("jsign health: %w", err)
	}

	err = runHealth(ctx, s.config.Run, s.config.HealthCommand)
	if err != nil {
		return fmt.Errorf("jsign health: %w", err)
	}

	return nil
}
