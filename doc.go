// Package codesign remotely Authenticode-signs Windows binaries with a key
// that lives on a hardware token (YubiKey PIV). This root package holds the
// HTTP client library used by the codesign CLI and the GitHub Action. The
// signing daemon lives in cmd/signerd, and the CLI lives in cmd/codesign.
package codesign
