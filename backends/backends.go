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
	"context"
	"fmt"
	"os"
	"os/exec"
)

const (
	// DefaultTimestampURL is SSL.com's RFC 3161 timestamp authority.
	DefaultTimestampURL = "http://ts.ssl.com"
	// LegacyTimestampURL is SSL.com's RSA timestamp authority, for tools
	// that reject ECDSA-signed timestamps.
	LegacyTimestampURL = "http://ts.ssl.com/legacy"
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

// copyFile copies a file for tools that only sign in place.
func copyFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("reading %s: %w", source, err)
	}

	const onlyOwner = 0o600

	err = os.WriteFile(destination, data, onlyOwner)
	if err != nil {
		return fmt.Errorf("writing %s: %w", destination, err)
	}

	return nil
}
