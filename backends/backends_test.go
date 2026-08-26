package backends_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	if f.err != nil {
		return f.output, f.err
	}

	// osslsigncode writes -out itself. Mimic that so publishSigned can rename.
	for i, arg := range args {
		if arg == "-out" && i+1 < len(args) {
			err := writeFakeOut(args[i+1])
			if err != nil {
				return f.output, err
			}
		}
	}

	return f.output, nil
}

func writeFakeOut(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking staging -out: %w", err)
	}

	err = os.WriteFile(path, []byte("signed"), 0o600)
	if err != nil {
		return fmt.Errorf("writing staging -out: %w", err)
	}

	return nil
}

func TestOSSLSigncodeSign(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "in.exe")
	output := filepath.Join(dir, "out.exe")

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
		InputPath:  input,
		OutputPath: output,
		Name:       "Request Name",
		URL:        "https://request.example.com",
	})
	require.NoError(t, err)
	require.FileExists(t, output, "successful sign must publish OutputPath")

	require.Len(t, runner.calls, 1)
	got := runner.calls[0]
	assert.Equal(t, []string{
		"/usr/bin/osslsigncode", "sign",
		"-pkcs11module", "/usr/lib/libykcs11.so",
		"-certs", "/etc/signerd/chain.pem",
		"-key", "pkcs11:id=%01",
		"-h", "sha384",
		"-ts", backends.DefaultTimestampURL,
	}, got[:12])
	assert.Equal(t, "-readpass", got[12])
	assert.True(t, strings.HasPrefix(filepath.Base(got[13]), "codesign-pin-"))
	assert.Equal(t, []string{
		"-n", "Request Name",
		"-i", "https://request.example.com",
		"-in", input, "-out",
	}, got[14:len(got)-1])
	assert.Equal(t, dir, filepath.Dir(got[len(got)-1]), "tool must write a sibling staging file")
	assert.NotEqual(t, output, got[len(got)-1], "OutputPath must not be the tool -out")
	assert.NotContains(t, got, "123456", "PIN must not appear in argv")
}

func TestOSSLSigncodeOutDoesNotExist(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "in.exe")
	output := filepath.Join(dir, "out.exe")

	require.NoError(t, os.WriteFile(input, []byte("MZ"), 0o600))

	var sawOut string

	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		CertFile:     "/etc/signerd/chain.pem",
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			sawOut = args[len(args)-1]
			_, err := os.Stat(sawOut)
			require.ErrorIs(t, err, os.ErrNotExist, "osslsigncode 2.5 cannot overwrite -out")
			require.NoError(t, os.WriteFile(sawOut, []byte("signed"), 0o600))

			return nil, nil
		},
	})

	err := backend.Sign(t.Context(), &signer.Request{InputPath: input, OutputPath: output})
	require.NoError(t, err)
	require.FileExists(t, output)
	assert.NotEqual(t, output, sawOut)
}

func TestOSSLSigncodeDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "in.exe")
	output := filepath.Join(dir, "out.exe")

	runner := &fakeRunner{}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		CertFile:     "/etc/signerd/chain.pem",
		Run:          runner.run,
	})

	err := backend.Sign(t.Context(), &signer.Request{InputPath: input, OutputPath: output})
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	got := runner.calls[0]
	assert.Equal(t, []string{
		"osslsigncode", "sign",
		"-pkcs11module", "/usr/lib/libykcs11.so",
		"-certs", "/etc/signerd/chain.pem",
		"-key", backends.DefaultKeyID,
		"-h", "sha384",
		"-ts", backends.DefaultTimestampURL,
		"-in", input, "-out",
	}, got[:len(got)-1], "default KeyID is PIV 9A; no PIN, name, or URL without configuration")
	assert.NotEqual(t, output, got[len(got)-1])
}

func TestOSSLSigncodeSignError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	output := filepath.Join(dir, "out.exe")
	errSign := errors.New("no token present")
	runner := &fakeRunner{err: errSign}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		CertFile:     "/etc/signerd/chain.pem",
		Run:          runner.run,
	})

	err := backend.Sign(t.Context(), &signer.Request{
		InputPath:  filepath.Join(dir, "in.exe"),
		OutputPath: output,
	})
	require.ErrorIs(t, err, errSign)
	assert.NoFileExists(t, output, "a failed sign must not leave OutputPath")
}

func TestSignRequiresConfig(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	dir := t.TempDir()
	req := &signer.Request{
		InputPath:  filepath.Join(dir, "in.exe"),
		OutputPath: filepath.Join(dir, "out.exe"),
	}

	err := backends.NewOSSLSigncode(&backends.OSSLConfig{CertFile: "chain.pem", Run: runner.run}).
		Sign(t.Context(), req)
	require.ErrorIs(t, err, backends.ErrNoPKCS11Module)

	err = backends.NewOSSLSigncode(&backends.OSSLConfig{PKCS11Module: "mod.so", Run: runner.run}).
		Sign(t.Context(), req)
	require.ErrorIs(t, err, backends.ErrNoCertFile)

	err = backends.NewJsign(&backends.JsignConfig{Run: runner.run}).Sign(t.Context(), req)
	require.ErrorIs(t, err, backends.ErrNoCertFile)

	assert.Empty(t, runner.calls, "the tool must not run without required config")
}

func TestOSSLSigncodeHealth(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{output: []byte("Certificate Object; type = X.509 cert")}
	backend := backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		Run:          runner.run,
	})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, runner.calls, 2)
	assert.Equal(t, []string{"osslsigncode", "--version"}, runner.calls[0])
	assert.Equal(t, []string{
		"pkcs11-tool", "--module", "/usr/lib/libykcs11.so",
		"--list-objects", "--type", "cert",
	}, runner.calls[1])

	headingOnly := &fakeRunner{output: []byte("Available slots:\n")}
	backend = backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		Run:          headingOnly.run,
	})
	err := backend.Health(t.Context())
	require.ErrorIs(t, err, backends.ErrNoToken)

	empty := &fakeRunner{}
	backend = backends.NewOSSLSigncode(&backends.OSSLConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		Run:          empty.run,
	})
	err = backend.Health(t.Context())
	require.ErrorIs(t, err, backends.ErrNoToken)

	custom := &fakeRunner{output: []byte("osslsigncode 2.9")}
	backend = backends.NewOSSLSigncode(&backends.OSSLConfig{
		Command:       "osc",
		HealthCommand: []string{"osc", "--version"},
		Run:           custom.run,
	})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, custom.calls, 2)
	assert.Equal(t, []string{"osc", "--version"}, custom.calls[0])
	assert.Equal(t, []string{"osc", "--version"}, custom.calls[1])
}

func TestSignRejectsContractViolations(t *testing.T) {
	t.Parallel()

	ossl := backends.NewOSSLSigncode(&backends.OSSLConfig{Run: (&fakeRunner{output: []byte("x")}).run})
	jsign := backends.NewJsign(&backends.JsignConfig{Run: (&fakeRunner{output: []byte("x")}).run})

	same := &signer.Request{InputPath: "same.exe", OutputPath: "same.exe"}

	for _, backend := range []signer.Signer{ossl, jsign} {
		require.ErrorIs(t, backend.Sign(t.Context(), nil), signer.ErrNilRequest)
		require.ErrorIs(t, backend.Sign(t.Context(), same), signer.ErrSamePath)
	}
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
	assert.Equal(t, "/usr/bin/jsign", runner.calls[0][0])
	assert.Contains(t, runner.calls[0], "--storetype")
	assert.Contains(t, runner.calls[0], "YUBIKEY")
	assert.Contains(t, runner.calls[0], "--alias")
	assert.Contains(t, runner.calls[0], "--tsmode")
	assert.Contains(t, runner.calls[0], "RFC3161")
	assert.NotContains(t, runner.calls[0], "123456", "PIN must not appear in argv")
	assert.NotEqual(t, output, runner.calls[0][len(runner.calls[0])-1], "jsign must sign a staging file")
	assert.Equal(t, dir, filepath.Dir(runner.calls[0][len(runner.calls[0])-1]))

	passAt := -1

	for i, arg := range runner.calls[0] {
		if arg == "--storepass" {
			passAt = i
		}
	}

	require.Positive(t, passAt)
	assert.True(t, strings.HasPrefix(runner.calls[0][passAt+1], "file:"))
}

func TestJsignSignPIVStoreType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	output := filepath.Join(dir, "app.exe.signed")

	require.NoError(t, os.WriteFile(input, []byte("MZ unsigned"), 0o600))

	runner := &fakeRunner{}
	backend := backends.NewJsign(&backends.JsignConfig{
		CertFile:  "/etc/signerd/chain.pem",
		StoreType: "PIV",
		Run:       runner.run,
	})
	assert.Equal(t, "PIV", backend.StoreType())

	err := backend.Sign(t.Context(), &signer.Request{InputPath: input, OutputPath: output})
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Contains(t, runner.calls[0], "--storetype")
	assert.Contains(t, runner.calls[0], "PIV")
	assert.NotContains(t, runner.calls[0], "YUBIKEY")
}

func TestJsignSignMissingInput(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{}
	output := filepath.Join(t.TempDir(), "out.exe")
	backend := backends.NewJsign(&backends.JsignConfig{
		CertFile: "/etc/signerd/chain.pem",
		Run:      runner.run,
	})

	err := backend.Sign(t.Context(), &signer.Request{
		InputPath:  filepath.Join(t.TempDir(), "missing.exe"),
		OutputPath: output,
	})
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, runner.calls, "jsign must not run when the copy fails")
	assert.NoFileExists(t, output, "a failed copy must not leave OutputPath")
}

func TestJsignSignErrorCleansOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	output := filepath.Join(dir, "app.exe.signed")

	require.NoError(t, os.WriteFile(input, []byte("MZ unsigned"), 0o600))

	errSign := errors.New("jsign failed")
	runner := &fakeRunner{err: errSign}
	backend := backends.NewJsign(&backends.JsignConfig{
		CertFile: "/etc/signerd/chain.pem",
		Run:      runner.run,
	})

	err := backend.Sign(t.Context(), &signer.Request{InputPath: input, OutputPath: output})
	require.ErrorIs(t, err, errSign)
	assert.NoFileExists(t, output, "a failed jsign must not leave an unsigned copy at OutputPath")
}

func TestJsignHealth(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{output: []byte("Certificate Object; type = X.509 cert")}
	backend := backends.NewJsign(&backends.JsignConfig{
		PKCS11Module: "/usr/lib/libykcs11.so",
		Run:          runner.run,
	})
	require.NoError(t, backend.Health(t.Context()))
	require.Len(t, runner.calls, 2)
	assert.Equal(t, []string{"jsign", "--version"}, runner.calls[0])
	assert.Equal(t, []string{
		"pkcs11-tool", "--module", "/usr/lib/libykcs11.so",
		"--list-objects", "--type", "cert",
	}, runner.calls[1])
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
