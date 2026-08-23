package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign/backends"
)

func TestBuildSignerJsignPassesModule(t *testing.T) {
	t.Parallel()

	module := filepath.Join(t.TempDir(), "libykcs11.so")
	backend, err := buildSigner(&Config{
		Backend:      "jsign",
		PKCS11Module: module,
		CertFile:     filepath.Join(t.TempDir(), "chain.pem"),
	})
	require.NoError(t, err)

	jsign, ok := backend.(*backends.Jsign)
	require.True(t, ok)
	assert.Equal(t, []string{
		"pkcs11-tool", "--module", module, "--list-objects", "--type", "cert",
	}, jsign.HealthCommand())
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	module := filepath.Join(dir, "libykcs11.so")
	cert := filepath.Join(dir, "chain.pem")

	require.NoError(t, os.WriteFile(module, []byte("so"), 0o600))
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

	require.NoError(t, validateConfig(&Config{PKCS11Module: module, CertFile: cert, PIN: "1"}))
	require.ErrorIs(t, validateConfig(&Config{CertFile: cert, PIN: "1"}), errNoPKCS11Module)
	require.ErrorIs(t, validateConfig(&Config{PKCS11Module: module, PIN: "1"}), errNoCertFile)
	require.Error(t, validateConfig(&Config{
		PKCS11Module: filepath.Join(dir, "missing.so"),
		CertFile:     cert,
		PIN:          "1",
	}))

	require.NoError(t, validateConfig(&Config{
		Backend:      "jsign",
		PKCS11Module: module,
		CertFile:     cert,
		PIN:          "1",
	}))
	require.ErrorIs(t, validateConfig(&Config{Backend: "jsign", CertFile: cert, PIN: "1"}), errNoJsignProbe)
	require.NoError(t, validateConfig(&Config{
		Backend:       "jsign",
		CertFile:      cert,
		HealthCommand: []string{"true"},
		PIN:           "1",
	}))
}

func TestValidateConfigMaxBody(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	module := filepath.Join(dir, "libykcs11.so")
	cert := filepath.Join(dir, "chain.pem")

	require.NoError(t, os.WriteFile(module, []byte("so"), 0o600))
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

	base := func(mib int64) *Config {
		return &Config{PKCS11Module: module, CertFile: cert, PIN: "1", MaxBodyMiB: mib}
	}

	require.NoError(t, validateConfig(base(0)), "zero means use the server default")
	require.NoError(t, validateConfig(base(100)))
	require.ErrorIs(t, validateConfig(base(-1)), errBadMaxBody)
	require.ErrorIs(t, validateConfig(base(math.MaxInt64/bytesPerMiB+1)), errBadMaxBody)
}

func TestValidateConfigRequiresAudience(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	module := filepath.Join(dir, "libykcs11.so")
	cert := filepath.Join(dir, "chain.pem")

	require.NoError(t, os.WriteFile(module, []byte("so"), 0o600))
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

	base := Config{PKCS11Module: module, CertFile: cert, PIN: "1"}

	require.NoError(t, validateConfig(&base), "empty allowlist disables remote signing; audience unused")

	base.Github.AllowedRepositories = []string{"golift/codesign"}
	require.ErrorIs(t, validateConfig(&base), errNoAudience)

	base.Github.Audience = "   "
	require.ErrorIs(t, validateConfig(&base), errNoAudience)

	base.Github.Audience = "https://sign.example.com"
	require.NoError(t, validateConfig(&base))
}

func TestValidateConfigRejectsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cert := filepath.Join(dir, "chain.pem")

	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

	err := validateConfig(&Config{PKCS11Module: dir, CertFile: cert, PIN: "1"})
	require.ErrorIs(t, err, errNotRegularFile)
}

func TestBuildSignerFakeRequiresEnv(t *testing.T) {
	t.Setenv(allowFakeEnv, "")

	require.ErrorIs(t, validateConfig(&Config{Backend: "fake"}), errFakeDisabled)

	_, err := buildSigner(&Config{Backend: "fake"})
	require.ErrorIs(t, err, errFakeDisabled)

	t.Setenv(allowFakeEnv, "1")
	require.NoError(t, validateConfig(&Config{Backend: "fake"}))

	backend, err := buildSigner(&Config{Backend: "fake"})
	require.NoError(t, err)
	require.NotNil(t, backend)
}
