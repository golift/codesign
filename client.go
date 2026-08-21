package codesign

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultTimeout covers upload, signing, and the timestamp round trip.
	DefaultTimeout = 5 * time.Minute
	// retryDelay separates retry attempts.
	retryDelay = 5 * time.Second
)

// Errors returned by the client.
var (
	ErrNoURL         = errors.New("no signing service URL configured")
	ErrHalfKeyPair   = errors.New("client certificate and key must both be set (or neither)")
	ErrNoActionsOIDC = errors.New("not running under GitHub Actions with id-token permission " +
		"(ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN are unset)")
	errSignFailed = errors.New("signing service error")
)

// Config builds a Client.
type Config struct {
	// URL is the base URL of signerd or the proxy in front of it, such as
	// https://sign.example.com or http://127.0.0.1:8750 over an SSH tunnel.
	URL string
	// ClientCert and ClientKey enable mTLS toward the proxy. Each may be a
	// file path or inline PEM (anything containing "-----BEGIN").
	ClientCert string
	// ClientKey is the private key matching ClientCert.
	ClientKey string
	// RootCA optionally pins the CA that signed the server certificate.
	// File path or inline PEM.
	RootCA string
	// Token is a GitHub Actions OIDC bearer token. Leave empty on loopback
	// or SSH-tunnel connections; required through the public proxy.
	Token string
	// Retries is how many times a failed request is retried (network errors
	// and gateway errors only; auth and validation failures never retry).
	Retries int
	// Timeout per attempt. Defaults to DefaultTimeout.
	Timeout time.Duration
}

// SignOptions carries per-file Authenticode fields. The zero value uses the
// daemon's configured defaults.
type SignOptions struct {
	// Name is the Authenticode program name.
	Name string
	// URL is the Authenticode program URL.
	URL string
}

// Client signs files against a remote signerd. Create one with New.
type Client struct {
	config Config
	web    *http.Client
}

// New validates the configuration, loads mTLS material, and returns a Client.
func New(config *Config) (*Client, error) {
	if config.URL == "" {
		return nil, ErrNoURL
	}

	client := &Client{config: *config}
	client.config.URL = strings.TrimSuffix(client.config.URL, "/")

	if client.config.Timeout == 0 {
		client.config.Timeout = DefaultTimeout
	}

	// A negative retry count would skip the request loop entirely and
	// "succeed" with no data.
	if client.config.Retries < 0 {
		client.config.Retries = 0
	}

	tlsConfig, err := buildTLS(&client.config)
	if err != nil {
		return nil, err
	}

	client.web = &http.Client{
		Timeout:   client.config.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	return client, nil
}

// Health checks the daemon's /health endpoint. No auth required.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.URL+HealthPath, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.web.Do(req)
	if err != nil {
		return fmt.Errorf("checking health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("%w: %s: %s", errSignFailed, resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}

// Sign posts file bytes to the signing service and returns the signed bytes.
// The filename is advisory; the daemon uses its extension to pick the
// signing format.
func (c *Client) Sign(ctx context.Context, filename string, data []byte, opts *SignOptions) ([]byte, error) {
	if opts == nil {
		opts = &SignOptions{}
	}

	var lastErr error

	for attempt := 0; attempt <= c.config.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("waiting to retry: %w", ctx.Err())
			case <-time.After(retryDelay):
			}
		}

		signed, retryable, err := c.signOnce(ctx, filename, data, opts)
		if err == nil {
			return signed, nil
		}

		lastErr = err

		if !retryable {
			break
		}
	}

	return nil, lastErr
}

// SignFile signs inputPath and writes the result to outputPath. An empty
// outputPath replaces the input file in place. The output is written to a
// temp file first and renamed, so a failure never truncates the target.
func (c *Client) SignFile(ctx context.Context, inputPath, outputPath string, opts *SignOptions) error {
	if outputPath == "" {
		outputPath = inputPath
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	signed, err := c.Sign(ctx, filepath.Base(inputPath), data, opts)
	if err != nil {
		return err
	}

	return writeAtomic(signed, inputPath, outputPath)
}

// writeAtomic writes the signed bytes next to the output path and renames
// them into place, preserving the mode of the file being replaced (or of the
// input) so an executable stays executable.
func writeAtomic(signed []byte, inputPath, outputPath string) error {
	temp, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".signing-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	_, err = temp.Write(signed)
	if err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())

		return fmt.Errorf("writing signed file: %w", err)
	}

	// A close error can mean the filesystem never flushed the data; do not
	// publish a possibly-incomplete artifact.
	err = temp.Close()
	if err != nil {
		_ = os.Remove(temp.Name())

		return fmt.Errorf("closing signed file: %w", err)
	}

	err = os.Chmod(temp.Name(), outputMode(inputPath, outputPath))
	if err != nil {
		_ = os.Remove(temp.Name())

		return fmt.Errorf("setting output permissions: %w", err)
	}

	err = os.Rename(temp.Name(), outputPath)
	if err != nil {
		_ = os.Remove(temp.Name())

		return fmt.Errorf("replacing output file: %w", err)
	}

	return nil
}

// outputMode picks the permission bits for the signed file: the mode of the
// file being replaced, falling back to the input file's, then owner-only.
func outputMode(inputPath, outputPath string) fs.FileMode {
	const onlyOwner fs.FileMode = 0o600

	info, err := os.Stat(outputPath)
	if err != nil {
		info, err = os.Stat(inputPath)
	}

	if err != nil {
		return onlyOwner
	}

	return info.Mode().Perm()
}

// signOnce performs one POST /v1/sign attempt. The second return value says
// whether the failure is worth retrying.
func (c *Client) signOnce(
	ctx context.Context,
	filename string,
	data []byte,
	opts *SignOptions,
) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.URL+SignPath, bytes.NewReader(data))
	if err != nil {
		return nil, false, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(HeaderFilename, filename)

	if opts.Name != "" {
		req.Header.Set(HeaderName, opts.Name)
	}

	if opts.URL != "" {
		req.Header.Set(HeaderURL, opts.URL)
	}

	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.web.Do(req)
	if err != nil {
		// TLS and certificate problems are configuration, not weather;
		// retrying them just delays the real error.
		return nil, !isPermanentTransportError(err), fmt.Errorf("posting file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		gateway := resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout

		return nil, gateway, fmt.Errorf("%w: %s: %s", errSignFailed, resp.Status, strings.TrimSpace(string(body)))
	}

	signed, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, fmt.Errorf("reading response: %w", err)
	}

	return signed, false, nil
}

// FetchGitHubToken requests an OIDC token from the GitHub Actions runtime
// with the provided audience. The calling workflow job must set
// permissions: id-token: write.
func FetchGitHubToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return "", ErrNoActionsOIDC
	}

	// The URL comes from the GitHub Actions runtime environment on purpose.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, //nolint:gosec
		requestURL+"&audience="+url.QueryEscape(audience), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+requestToken)

	resp, err := (&http.Client{Timeout: DefaultTimeout}).Do(req) //nolint:gosec // Same env-provided URL.
	if err != nil {
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return "", fmt.Errorf("%w: %s: %s", errSignFailed, resp.Status, strings.TrimSpace(string(body)))
	}

	token := struct {
		Value string `json:"value"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return "", fmt.Errorf("decoding OIDC token: %w", err)
	}

	return token.Value, nil
}

// isPermanentTransportError reports whether a transport failure cannot be
// fixed by retrying: TLS handshake rejections and certificate verification
// failures, as opposed to transient network weather.
func isPermanentTransportError(err error) bool {
	var (
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		alertErr    tls.AlertError
		unknownCA   x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		certErr     x509.CertificateInvalidError
	)

	return errors.As(err, &verifyErr) ||
		errors.As(err, &recordErr) ||
		errors.As(err, &alertErr) ||
		errors.As(err, &unknownCA) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &certErr)
}

// buildTLS assembles the client TLS configuration from the mTLS settings.
// It returns nil when neither a client certificate nor a root CA is set.
func buildTLS(config *Config) (*tls.Config, error) {
	// Half an mTLS pair is a configuration mistake; ignoring it silently
	// would present no certificate while the caller believes mTLS is on.
	if (config.ClientKey == "") != (config.ClientCert == "") {
		return nil, ErrHalfKeyPair
	}

	if config.ClientCert == "" && config.RootCA == "" {
		return nil, nil //nolint:nilnil // nil TLS config selects http defaults.
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if config.ClientCert != "" {
		cert, err := loadKeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.RootCA != "" {
		caPEM, err := loadPEM(config.RootCA)
		if err != nil {
			return nil, fmt.Errorf("loading root CA: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parsing root CA: %w", errNoCertsInPEM)
		}

		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// loadKeyPair loads the mTLS client certificate and key, each from a file
// path or inline PEM.
func loadKeyPair(certValue, keyValue string) (tls.Certificate, error) {
	certPEM, err := loadPEM(certValue)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading client certificate: %w", err)
	}

	keyPEM, err := loadPEM(keyValue)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading client key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing client certificate: %w", err)
	}

	return cert, nil
}

// errNoCertsInPEM means the root CA PEM contained no usable certificates.
var errNoCertsInPEM = errors.New("no certificates found in PEM")

// loadPEM accepts inline PEM (contains "-----BEGIN") or a file path.
func loadPEM(value string) ([]byte, error) {
	if strings.Contains(value, "-----BEGIN") {
		return []byte(value), nil
	}

	data, err := os.ReadFile(value)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", value, err)
	}

	return data, nil
}
