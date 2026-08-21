package signer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Errors returned by Fake when a caller violates the Signer contract.
var (
	// ErrNilRequest is returned when Sign receives a nil request.
	ErrNilRequest = errors.New("nil sign request")
	// ErrSamePath is returned when a request uses one path for both input
	// and output; the Signer contract forbids in-place signing.
	ErrSamePath = errors.New("input and output paths may not be the same file")
)

// FakeMarker is appended to the output file by Fake.Sign so tests can verify
// a file passed through the fake backend.
const FakeMarker = "\nFAKE-AUTHENTICODE-SIGNATURE\n"

// Fake is a Signer for tests. It copies the input file to the output path,
// appends FakeMarker, and records every request it receives. Set SignErr or
// HealthErr to make the respective method fail. Fake is safe for concurrent
// use.
type Fake struct {
	mu sync.Mutex
	// SignErr is returned by Sign when set. The request is still recorded.
	SignErr error
	// HealthErr is returned by Health when set.
	HealthErr error
	// requests holds every request passed to Sign.
	requests []Request
}

// Sign records the request, then copies the input file to the output path
// with FakeMarker appended. It enforces the Signer contract so tests catch
// callers that pass a nil request or sign in place.
func (f *Fake) Sign(_ context.Context, req *Request) error {
	if req == nil {
		return ErrNilRequest
	}

	if req.InputPath == req.OutputPath {
		return fmt.Errorf("%w: %s", ErrSamePath, req.InputPath)
	}

	f.mu.Lock()
	f.requests = append(f.requests, *req)
	err := f.SignErr
	f.mu.Unlock()

	if err != nil {
		return err
	}

	data, err := os.ReadFile(req.InputPath)
	if err != nil {
		return fmt.Errorf("fake signer reading input: %w", err)
	}

	const onlyOwner = 0o600

	err = os.WriteFile(req.OutputPath, append(data, []byte(FakeMarker)...), onlyOwner)
	if err != nil {
		return fmt.Errorf("fake signer writing output: %w", err)
	}

	return nil
}

// Health returns HealthErr.
func (f *Fake) Health(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.HealthErr
}

// Requests returns a copy of every request passed to Sign.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Request, len(f.requests))
	copy(out, f.requests)

	return out
}
