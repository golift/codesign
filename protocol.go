package codesign

// The signerd HTTP protocol, shared by the daemon, the client library, and
// the CLI. POST the raw PE/MSI bytes to SignPath and read the signed bytes
// back. Callers authenticate with a GitHub Actions OIDC bearer token. Loopback
// peers may skip that check, but only when the daemon is explicitly configured
// to allow it (AllowUnauthenticatedLoopback); by default every caller, loopback
// or not, must present a token.
const (
	// SignPath accepts a POST with the unsigned file as the request body and
	// returns the signed file as the response body.
	SignPath = "/v1/sign"
	// HealthPath reports whether the daemon can sign right now. No auth.
	HealthPath = "/health"
	// HeaderFilename carries the original file name so the daemon can pick
	// the right signing format from the extension.
	HeaderFilename = "X-Codesign-Filename"
	// HeaderName carries the Authenticode program name. Optional.
	HeaderName = "X-Codesign-Name"
	// HeaderURL carries the Authenticode program URL. Optional.
	HeaderURL = "X-Codesign-Url"
)
