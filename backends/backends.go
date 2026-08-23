// Package backends implements the signer.Signer interface on top of external
// signing tools: osslsigncode (PKCS#11 against libykcs11) and jsign (native
// YubiKey store). Both backends shell out through an injectable Runner so
// tests never need a tool or a token.
//
// The signing key on the token is ECC P-384, so the default digest is SHA-384
// and timestamps come from SSL.com's RFC 3161 endpoint. Tools that reject
// ECDSA timestamps can be pointed at LegacyTimestampURL instead.
package backends

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	// ErrNoToken is returned by Health when the probe ran but produced no
	// output, which usually means the configured token is unplugged.
	ErrNoToken = errors.New("health check produced no token or certificate output")
	// ErrNoPKCS11Module is returned by Sign when osslsigncode has no module path.
	ErrNoPKCS11Module = errors.New("pkcs11 module path is required")
	// ErrNoCertFile is returned by Sign when the certificate chain path is empty.
	ErrNoCertFile = errors.New("certificate chain file is required")

	errNoHealthCommand = errors.New("health command is empty")
)

const (
	// DefaultTimestampURL is SSL.com's RFC 3161 timestamp authority.
	DefaultTimestampURL = "http://ts.ssl.com"
	// LegacyTimestampURL is SSL.com's RSA timestamp authority, for tools
	// that reject ECDSA-signed timestamps.
	LegacyTimestampURL = "http://ts.ssl.com/legacy"
	// DefaultKeyID is the PKCS#11 URI for PIV slot 9A (id %01), the
	// conventional code-signing slot. osslsigncode requires -key even when
	// the module exposes a single private key.
	DefaultKeyID   = "pkcs11:id=%01"
	certObjectMark = "Certificate Object"
)

// Runner executes one external command and returns its combined output.
// Inject a fake in tests; use Exec in production.
type Runner func(ctx context.Context, command string, args ...string) ([]byte, error)

// Exec is the production Runner. It runs the command with os/exec and folds
// the combined output into the returned error so signing failures are
// debuggable from one log line.
func Exec(ctx context.Context, command string, args ...string) ([]byte, error) {
	// Running the operator-configured signing tool is the entire point here.
	output, err := exec.CommandContext(ctx, command, args...).CombinedOutput() //nolint:gosec
	if err != nil {
		return output, fmt.Errorf("running %s: %w: %s", command, err, string(output))
	}

	return output, nil
}

// fallback returns the first non-empty string.
func fallback(request, configured string) string {
	if request != "" {
		return request
	}

	return configured
}

// copyFile streams a file copy for tools that only sign in place. Inputs can
// be large (MSI especially), so the copy never buffers the whole file.
func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("opening %s: %w", source, err)
	}
	defer input.Close()

	const onlyOwner = 0o600

	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, onlyOwner)
	if err != nil {
		return fmt.Errorf("creating %s: %w", destination, err)
	}

	_, err = io.Copy(output, input)
	if err != nil {
		_ = output.Close()

		return fmt.Errorf("copying to %s: %w", destination, err)
	}

	err = output.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", destination, err)
	}

	return nil
}

// publishSigned runs write against a sibling staging file, then renames it
// onto output so OutputPath only appears after a successful sign. A failed
// sign leaves neither a partial -out nor an unsigned copy at the target.
func publishSigned(output string, write func(staging string) error) error {
	dir := filepath.Dir(output)
	if dir == "" {
		dir = "."
	}

	staging, err := os.CreateTemp(dir, "."+filepath.Base(output)+".signing-*")
	if err != nil {
		return fmt.Errorf("creating staging file: %w", err)
	}

	path := staging.Name()

	err = staging.Close()
	if err != nil {
		_ = os.Remove(path)

		return fmt.Errorf("closing staging file: %w", err)
	}

	published := false

	defer func() {
		if !published {
			_ = os.Remove(path)
		}
	}()

	err = write(path)
	if err != nil {
		return err
	}

	err = os.Rename(path, output)
	if err != nil {
		return fmt.Errorf("publishing signed file: %w", err)
	}

	published = true

	return nil
}

// runHealth runs the configured health command. Token probes that list
// certificates must actually show a certificate object; a heading with no
// token (or an unrelated token with no certs) is unhealthy.
func runHealth(ctx context.Context, run Runner, command []string) error {
	if len(command) == 0 {
		return errNoHealthCommand
	}

	output, err := run(ctx, command[0], command[1:]...)
	if err != nil {
		return err
	}

	if len(bytes.TrimSpace(output)) == 0 {
		return ErrNoToken
	}

	if listsCertificates(command) && !bytes.Contains(output, []byte(certObjectMark)) {
		return ErrNoToken
	}

	return nil
}

func listsCertificates(command []string) bool {
	hasList, hasCert := false, false

	for i, arg := range command {
		if arg == "--list-objects" {
			hasList = true
		}

		if arg == "--type" && i+1 < len(command) && command[i+1] == "cert" {
			hasCert = true
		}
	}

	return hasList && hasCert
}

// defaultTokenHealth is a PIN-free PKCS#11 certificate listing. A module
// path is required: without one, pkcs11-tool --list-token-slots reports
// "Available slots:" even when no YubiKey is present.
func defaultTokenHealth(module string) []string {
	if module == "" {
		return nil
	}

	return []string{"pkcs11-tool", "--module", module, "--list-objects", "--type", "cert"}
}

// withPINFile writes the PIN to a 0600 temp file, calls fn with that path,
// and removes the file. An empty PIN skips the file (fn receives "").
func withPINFile(pin string, use func(path string) error) error {
	if pin == "" {
		return use("")
	}

	file, err := os.CreateTemp("", "codesign-pin-*")
	if err != nil {
		return fmt.Errorf("creating pin file: %w", err)
	}

	path := file.Name()
	defer os.Remove(path)

	_, err = file.WriteString(pin)
	closeErr := file.Close()

	if err != nil {
		return fmt.Errorf("writing pin file: %w", err)
	}

	if closeErr != nil {
		return fmt.Errorf("closing pin file: %w", closeErr)
	}

	return use(path)
}
