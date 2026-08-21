// Package signer defines the interface every signing backend implements, and
// provides a Fake backend for tests. Real backends (osslsigncode, jsign) wrap
// external tools that talk to the hardware token; nothing in this package
// touches a YubiKey.
package signer

import "context"

// Request describes one file to Authenticode-sign. The file is already on
// local disk; backends read InputPath and write OutputPath. InputPath and
// OutputPath may not be the same file.
type Request struct {
	// InputPath is the unsigned PE or MSI file.
	InputPath string
	// OutputPath is where the signed file is written.
	OutputPath string
	// Name is the Authenticode program name embedded in the signature.
	// Optional; backends fall back to their configured default.
	Name string
	// URL is the Authenticode program URL embedded in the signature.
	// Optional; backends fall back to their configured default.
	URL string
}

// Signer signs a single PE or MSI file. Implementations are not required to
// be safe for concurrent signing; the daemon serializes calls with a mutex
// because the hardware token handles one operation at a time.
type Signer interface {
	// Sign signs Request.InputPath and writes Request.OutputPath.
	Sign(ctx context.Context, req *Request) error
	// Health reports whether the backend can sign right now: the signing
	// tool is runnable and the token is present. It must not require a PIN.
	Health(ctx context.Context) error
}
