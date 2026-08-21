package backends_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign/backends"
	"golift.io/codesign/signer"
)

// fakeRunner records every command it is asked to run.
type fakeRunner struct {
	mu     sync.Mutex
	calls  [][]string
	output []byte
	err    error
}

func (f *fakeRunner) run(_ context.Context, command string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, append([]string{command}, args...))

	return f.output, f.err
}

func TestOSSLSigncodeSign(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		Command:      "/usr/bin/osslsigncode",
		PKCS11Module: "/usr/lib/libykcs11.so",
		CertFile:     "/etc/signerd/chain.pem",
		KeyID:        "pkcs11:id=%01",
		PIN:          "123456",
		Name:         "Default Name",
		URL:          "https://default.example.com",
		Run:          runner.run,
	})
	require.Implements(t, (*signer.Signer)(nil), backend)

	err := backend.Sign(t.Context(), &signer.Request{
		InputPath:  "/tmp/in.exe",
		OutputPath: "/tmp/out.exe",
		Name:       "Request Name",
		URL:        "https://request.example.com",
	})
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{
		"/usr/bin/osslsigncode", "sign",
		"-pkcs11module", "/usr/lib/libykcs11.so",
		"-certs", "/etc/signerd/chain.pem",
		"-h", "sha384",
		"-ts", backends.DefaultTimestampURL,
		"-key", "pkcs11:id=%01",
		"-pass", "123456",
		"-n", "Request Name",
		"-i", "https://request.example.com",
		"-in", "/tmp/in.exe",
		"-out", "/tmp/out.exe",
	}, runner.calls[0])
}

func TestOSSLSigncodeDefaults(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		CertFile:     "/etc/signerd/chain.pem",
		Run:          runner.run,
	})

	err := backend.Sign(t.Context(), &signer.Request{InputPath: "in.exe", OutputPath: "out.exe"})
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{
		"osslsigncode", "sign",
		"-pkcs11module", "/usr/lib/libykcs11.so",
		"-certs", "/etc/signerd/chain.pem",
		"-h", "sha384",
		"-ts", backends.DefaultTimestampURL,
		"-in", "in.exe",
		"-out", "out.exe",
	}, runner.calls[0], "no -key, -pass, -n, or -i without configuration")
}

func TestOSSLSigncodeSignError(t *testing.T) {
	t.Parallel()

	errSign := errors.New("no token present")
	runner := &fakeRunner{err: errSign}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{Run: runner.run})

	err := backend.Sign(t.Context(), &signer.Request{InputPath: "in", OutputPath: "out"})
	require.ErrorIs(t, err, errSign)
}

func TestOSSLSigncodeHealth(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{Command: "osc", Run: runner.run})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{"osc", "--version"}, runner.calls[0])

	// A custom health command may run a different program entirely, so
	// operators can point it at something that touches the token.
	custom := &fakeRunner{}
	backend = backends.NewOSSLSigncode(&backends.OSSLConfig{
		Command:       "osc",
		HealthCommand: []string{"pkcs11-tool", "--module", "/usr/lib/libykcs11.so", "--list-token-slots"},
		Run:           custom.run,
	})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, custom.calls, 1)
	assert.Equal(t, []string{"pkcs11-tool", "--module", "/usr/lib/libykcs11.so", "--list-token-slots"}, custom.calls[0])
}

func TestNilConfigsDoNotPanic(t *testing.T) {
	t.Parallel()

	require.NotNil(t, backends.NewOSSLSigncode(nil))
	require.NotNil(t, backends.NewJsign(nil))
}

func TestJsignSign(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	output := filepath.Join(dir, "app.exe.signed")

	require.NoError(t, os.WriteFile(input, []byte("MZ unsigned"), 0o600))

	runner := &fakeRunner{}
	backend := backends.NewJsign(&backends.JsignConfig{
		Command:  "/usr/bin/jsign",
		Alias:    "X.509 Certificate for PIV Authentication",
		CertFile: "/etc/signerd/chain.pem",
		PIN:      "123456",
		Run:      runner.run,
	})
	require.Implements(t, (*signer.Signer)(nil), backend)

	err := backend.Sign(t.Context(), &signer.Request{
		InputPath:  input,
		OutputPath: output,
		Name:       "My App",
		URL:        "https://app.example.com",
	})
	require.NoError(t, err)

	copied, err := os.ReadFile(output)
	require.NoError(t, err, "jsign signs in place, so the input must be copied to the output first")
	assert.Equal(t, "MZ unsigned", string(copied))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{
		"/usr/bin/jsign",
		"--storetype", "YUBIKEY",
		"--certfile", "/etc/signerd/chain.pem",
		"--alg", "SHA-384",
		"--tsaurl", backends.DefaultTimestampURL,
		"--alias", "X.509 Certificate for PIV Authentication",
		"--storepass", "123456",
		"--name", "My App",
		"--url", "https://app.example.com",
		output,
	}, runner.calls[0])
}

func TestJsignSignMissingInput(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	backend := backends.NewJsign(&backends.JsignConfig{Run: runner.run})

	err := backend.Sign(t.Context(), &signer.Request{
		InputPath:  filepath.Join(t.TempDir(), "missing.exe"),
		OutputPath: filepath.Join(t.TempDir(), "out.exe"),
	})
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, runner.calls, "jsign must not run when the copy fails")
}

func TestJsignHealth(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	backend := backends.NewJsign(&backends.JsignConfig{Run: runner.run})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{"jsign", "--help"}, runner.calls[0])
}

func TestExec(t *testing.T) {
	t.Parallel()

	// The Go toolchain is the one binary guaranteed on every CI runner.
	output, err := backends.Exec(t.Context(), "go", "version")
	require.NoError(t, err)
	assert.Contains(t, string(output), "go version")

	_, err = backends.Exec(t.Context(), "this-command-does-not-exist-xyz")
	require.Error(t, err)
}
