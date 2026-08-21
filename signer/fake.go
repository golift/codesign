package signer

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
)

// FakeMarker is appended to the output file by Fake.Sign so tests can verify
// a file passed through the fake backend.
const FakeMarker = "\nFAKE-AUTHENTICODE-SIGNATURE\n"

// Fake is a Signer for tests. It copies the input file to the output path,
// appends FakeMarker, and records every request it receives. Use SetSignErr
// or SetHealthErr to make the respective method fail; do not assign those
// fields from another goroutine without the setters. Fake is safe for
// concurrent Sign/Health/Requests once constructed.
type Fake struct {
	mu        sync.Mutex
	signErr   error
	healthErr error
	requests  []Request
}

// SetSignErr sets the error Sign returns. The request is still recorded.
// Safe to call concurrently with Sign.
func (f *Fake) SetSignErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.signErr = err
}

// SetHealthErr sets the error Health returns. Safe to call concurrently
// with Health.
func (f *Fake) SetHealthErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.healthErr = err
}

// Sign records the request, then streams the input file to the output path
// with FakeMarker appended. It enforces the Signer contract so tests catch
// callers that pass a nil request or sign in place.
func (f *Fake) Sign(_ context.Context, req *Request) error {
	err := Check(req)
	if err != nil {
		return err
	}

	f.mu.Lock()
	f.requests = append(f.requests, *req)
	signErr := f.signErr
	f.mu.Unlock()

	if signErr != nil {
		return signErr
	}

	return copyWithMarker(req.InputPath, req.OutputPath)
}

// copyWithMarker streams input to output and appends FakeMarker, so tests
// never buffer a whole PE/MSI in memory.
func copyWithMarker(inputPath, outputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("fake signer reading input: %w", err)
	}
	defer input.Close()

	const onlyOwner = 0o600

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, onlyOwner)
	if err != nil {
		return fmt.Errorf("fake signer creating output: %w", err)
	}

	_, err = io.Copy(output, input)
	if err != nil {
		_ = output.Close()

		return fmt.Errorf("fake signer copying input: %w", err)
	}

	_, err = output.WriteString(FakeMarker)
	if err != nil {
		_ = output.Close()

		return fmt.Errorf("fake signer writing marker: %w", err)
	}

	err = output.Close()
	if err != nil {
		return fmt.Errorf("fake signer closing output: %w", err)
	}

	return nil
}

// Health returns the error set by SetHealthErr, if any.
func (f *Fake) Health(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.healthErr
}

// Requests returns a copy of every request passed to Sign.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Request, len(f.requests))
	copy(out, f.requests)

	return out
}
