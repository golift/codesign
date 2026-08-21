package backends

import (
	"context"
	"fmt"

	"golift.io/codesign/signer"
)

// OSSLConfig configures the osslsigncode backend.
type OSSLConfig struct {
	// Command is the osslsigncode binary. Defaults to "osslsigncode".
	Command string
	// PKCS11Module is the PKCS#11 module that reaches the token, such as
	// /usr/lib/x86_64-linux-gnu/libykcs11.so on Linux or
	// /opt/homebrew/lib/libykcs11.dylib on macOS. Required.
	PKCS11Module string
	// CertFile is the PEM file holding the full code-signing certificate
	// chain. Ship it next to the daemon; it is public but not committed.
	CertFile string
	// KeyID optionally selects the token key, as a PKCS#11 URI or ID, when
	// the module exposes more than one.
	KeyID string
	// PIN is the token user PIN. It is written to a 0600 temp file and
	// passed as -readpass so it never appears in process argv. Never the PUK.
	PIN string
	// TimestampURL defaults to DefaultTimestampURL.
	TimestampURL string
	// Digest defaults to sha384 to match an ECC P-384 signing key.
	Digest string
	// Name is the default Authenticode program name.
	Name string
	// URL is the default Authenticode program URL.
	URL string
	// HealthCommand is the full health-check command (program + args).
	// The default is a PIN-free pkcs11-tool probe of PKCS11Module that
	// fails when the token is unplugged. Override to target a specific
	// slot or certificate label. It must never need the PIN.
	HealthCommand []string
	// Run defaults to Exec.
	Run Runner
}

// OSSLSigncode signs PE and MSI files by invoking osslsigncode with a
// PKCS#11 module. It implements signer.Signer.
type OSSLSigncode struct {
	config OSSLConfig
}

// NewOSSLSigncode returns an osslsigncode backend with defaults applied.
// A nil config gets pure defaults.
func NewOSSLSigncode(config *OSSLConfig) *OSSLSigncode {
	if config == nil {
		config = &OSSLConfig{}
	}

	backend := &OSSLSigncode{config: *config}

	if backend.config.Command == "" {
		backend.config.Command = "osslsigncode"
	}

	if backend.config.TimestampURL == "" {
		backend.config.TimestampURL = DefaultTimestampURL
	}

	if backend.config.Digest == "" {
		backend.config.Digest = "sha384"
	}

	if backend.config.KeyID == "" {
		backend.config.KeyID = DefaultKeyID
	}

	if len(backend.config.HealthCommand) == 0 {
		backend.config.HealthCommand = defaultTokenHealth(backend.config.PKCS11Module)
	}

	if backend.config.Run == nil {
		backend.config.Run = Exec
	}

	return backend
}

// Sign invokes osslsigncode to sign the request input into the output path.
func (s *OSSLSigncode) Sign(ctx context.Context, req *signer.Request) error {
	err := signer.Check(req)
	if err != nil {
		return fmt.Errorf("osslsigncode sign: %w", err)
	}

	return withPINFile(s.config.PIN, func(pinPath string) error {
		args := []string{
			"sign",
			"-pkcs11module", s.config.PKCS11Module,
			"-certs", s.config.CertFile,
			"-key", s.config.KeyID,
			"-h", s.config.Digest,
			"-ts", s.config.TimestampURL,
		}

		if pinPath != "" {
			args = append(args, "-readpass", pinPath)
		}

		if name := fallback(req.Name, s.config.Name); name != "" {
			args = append(args, "-n", name)
		}

		if url := fallback(req.URL, s.config.URL); url != "" {
			args = append(args, "-i", url)
		}

		args = append(args, "-in", req.InputPath, "-out", req.OutputPath)

		_, err := s.config.Run(ctx, s.config.Command, args...)
		if err != nil {
			return fmt.Errorf("osslsigncode sign: %w", err)
		}

		return nil
	})
}

// Health proves the signing tool is runnable and the token is present.
func (s *OSSLSigncode) Health(ctx context.Context) error {
	_, err := s.config.Run(ctx, s.config.Command, "--version")
	if err != nil {
		return fmt.Errorf("osslsigncode health: %w", err)
	}

	err = runHealth(ctx, s.config.Run, s.config.HealthCommand)
	if err != nil {
		return fmt.Errorf("osslsigncode health: %w", err)
	}

	return nil
}
