// Package signer defines the interface every signing backend implements, and
// provides a Fake backend for tests. Real backends (osslsigncode, jsign) wrap
// external tools that talk to the hardware token; nothing in this package
// touches a YubiKey.
package signer

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Errors returned when a caller violates the Signer contract.
var (
	// ErrNilRequest is returned when Sign receives a nil request.
	ErrNilRequest = errors.New("nil sign request")
	// ErrSamePath is returned when a request uses one path for both input
	// and output, including aliases (hard links, symlinks). The Signer
	// contract forbids in-place signing.
	ErrSamePath = errors.New("input and output paths may not be the same file")
)

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

// Check enforces the Signer request contract: the request is non-nil, and
// InputPath / OutputPath are not the same file (lexical match or os.SameFile
// for hard links, symlinks, and case-folded aliases).
func Check(req *Request) error {
	if req == nil {
		return ErrNilRequest
	}

	if req.InputPath == req.OutputPath {
		return fmt.Errorf("%w: %s", ErrSamePath, req.InputPath)
	}

	if sameFile(req.InputPath, req.OutputPath) {
		return fmt.Errorf("%w: %s", ErrSamePath, req.InputPath)
	}

	return nil
}

// sameFile reports whether both paths already exist and refer to one inode.
// A missing path is not treated as a match; the lexical check above covers
// the usual in-place case before either file is created.
func sameFile(left, right string) bool {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false
	}

	rightInfo, err := os.Stat(right)
	if err != nil {
		return false
	}

	return os.SameFile(leftInfo, rightInfo)
}
