package main

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
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
	assert.Equal(t, "YUBIKEY", jsign.StoreType())
}

func TestBuildSignerJsignPassesStoreType(t *testing.T) {
	t.Parallel()

	backend, err := buildSigner(&Config{
		Backend:       "jsign",
		StoreType:     "PIV",
		HealthCommand: []string{"ykman", "piv", "info"},
		CertFile:      filepath.Join(t.TempDir(), "chain.pem"),
	})
	require.NoError(t, err)

	jsign, ok := backend.(*backends.Jsign)
	require.True(t, ok)
	assert.Equal(t, "PIV", jsign.StoreType())
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

func TestDefaultConfigCandidates(t *testing.T) {
	t.Parallel()

	candidates := defaultConfigCandidates()
	require.NotEmpty(t, candidates)

	for _, candidate := range candidates {
		assert.Equal(t, configFileName, filepath.Base(candidate))
	}

	if runtime.GOOS == "windows" {
		assert.NotContains(t, candidates, filepath.Join(unixSystemDir, configFileName))
		assert.Equal(t, `ProgramData\signerd`, systemConfigHint())

		programData := os.Getenv("ProgramData")
		if programData != "" {
			assert.Contains(t, candidates, filepath.Join(programData, "signerd", configFileName))
		}

		return
	}

	assert.Contains(t, candidates, filepath.Join(unixSystemDir, configFileName))
	assert.Equal(t, unixSystemDir, systemConfigHint())
}

func TestLoadConfigStoreType(t *testing.T) {
	path := filepath.Join(t.TempDir(), configFileName)
	require.NoError(t, os.WriteFile(path, []byte("store_type = \"PKCS11\"\n"), 0o600))

	t.Run("toml", func(t *testing.T) {
		t.Setenv("SIGNERD_STORE_TYPE", "unused")
		require.NoError(t, os.Unsetenv("SIGNERD_STORE_TYPE"))

		config, err := loadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "PKCS11", config.StoreType)
	})

	t.Run("env", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), configFileName)
		require.NoError(t, os.WriteFile(empty, []byte("listen = \"127.0.0.1:8750\"\n"), 0o600))
		t.Setenv("SIGNERD_STORE_TYPE", "PIV")

		config, err := loadConfig(empty)
		require.NoError(t, err)
		assert.Equal(t, "PIV", config.StoreType)
	})

	t.Run("envOverridesTOML", func(t *testing.T) {
		t.Setenv("SIGNERD_STORE_TYPE", "PIV")

		config, err := loadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "PIV", config.StoreType)
	})
}

func TestFirstExistingConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.toml")
	present := filepath.Join(dir, "present.toml")

	require.NoError(t, os.WriteFile(present, []byte("listen = \"127.0.0.1:8750\"\n"), 0o600))

	assert.Empty(t, firstExistingConfig(nil))
	assert.Empty(t, firstExistingConfig([]string{missing}))
	assert.Equal(t, present, firstExistingConfig([]string{missing, present}))
	assert.Equal(t, present, firstExistingConfig([]string{present, missing}))
}
