package signer_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golift.io/codesign/signer"
)

func TestFakeSign(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	input := filepath.Join(dir, "app.exe")
	output := filepath.Join(dir, "app.exe.signed")

	require.NoError(t, os.WriteFile(input, []byte("MZ fake binary"), 0o600))

	fake := &signer.Fake{}
	req := &signer.Request{
		InputPath:  input,
		OutputPath: output,
		Name:       "Test App",
		URL:        "https://app.example.com",
	}
	require.NoError(t, fake.Sign(t.Context(), req))

	signed, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(signed), "MZ fake binary"), "output must contain the input")
	assert.True(t, strings.HasSuffix(string(signed), signer.FakeMarker), "output must end with the fake marker")

	requests := fake.Requests()
	require.Len(t, requests, 1)
	assert.Equal(t, *req, requests[0])
}

func TestFakeSignError(t *testing.T) {
	t.Parallel()

	errBroken := errors.New("token unplugged")
	fake := &signer.Fake{SignErr: errBroken}
	req := &signer.Request{InputPath: "in", OutputPath: "out"}

	err := fake.Sign(t.Context(), req)
	require.ErrorIs(t, err, errBroken)
	assert.Len(t, fake.Requests(), 1, "failed requests are still recorded")
}

func TestFakeSignMissingInput(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	err := fake.Sign(t.Context(), &signer.Request{
		InputPath:  filepath.Join(t.TempDir(), "missing.exe"),
		OutputPath: filepath.Join(t.TempDir(), "out.exe"),
	})
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestFakeHealth(t *testing.T) {
	t.Parallel()

	fake := &signer.Fake{}
	require.NoError(t, fake.Health(t.Context()))

	errDown := errors.New("pcscd is down")
	fake.HealthErr = errDown
	require.ErrorIs(t, fake.Health(t.Context()), errDown)
}
