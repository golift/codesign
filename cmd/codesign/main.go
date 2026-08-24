// codesign is the CLI half of golift.io/codesign. It POSTs PE/MSI files to a
// signerd daemon and writes back the Authenticode-signed result. It is what
// the golift/codesign GitHub Action runs, and what operators run over an SSH
// tunnel.
//
// The connection and signing flags fall back to CODESIGN_* environment
// variables, so CI needs no argument plumbing: CODESIGN_URL,
// CODESIGN_CLIENT_CERT, CODESIGN_CLIENT_KEY, CODESIGN_CA_CERT,
// CODESIGN_TOKEN, CODESIGN_NAME, CODESIGN_WEBSITE. The remaining flags
// (-output, -retries, -timeout, -health, -version) are command-line only.
//
// When run inside GitHub Actions without an explicit token, it requests an
// OIDC token from the Actions runtime using the service URL as the audience.
// The workflow job must set permissions: id-token: write.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golift.io/codesign"
	"golift.io/version"
)

var errNoFiles = errors.New("no files to sign; pass file paths as arguments")

type flags struct {
	url     string
	cert    string
	key     string
	rootCA  string
	token   string
	name    string
	website string
	output  string
	retries int
	timeout time.Duration
	health  bool
	version bool
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "codesign:", err)
		os.Exit(1)
	}
}

func parseFlags() *flags {
	opts := &flags{}

	flag.StringVar(&opts.url, "url", os.Getenv("CODESIGN_URL"), "signing service URL (env CODESIGN_URL)")
	flag.StringVar(&opts.cert, "cert", os.Getenv("CODESIGN_CLIENT_CERT"),
		"mTLS client certificate, path or inline PEM (env CODESIGN_CLIENT_CERT)")
	flag.StringVar(&opts.key, "key", os.Getenv("CODESIGN_CLIENT_KEY"),
		"mTLS client key, path or inline PEM (env CODESIGN_CLIENT_KEY)")
	flag.StringVar(&opts.rootCA, "ca", os.Getenv("CODESIGN_CA_CERT"),
		"CA certificate that signed the server cert, path or inline PEM (env CODESIGN_CA_CERT)")
	flag.StringVar(&opts.token, "token", os.Getenv("CODESIGN_TOKEN"),
		"OIDC bearer token; auto-fetched under GitHub Actions when empty (env CODESIGN_TOKEN)")
	flag.StringVar(&opts.name, "name", os.Getenv("CODESIGN_NAME"),
		"Authenticode program name (env CODESIGN_NAME)")
	flag.StringVar(&opts.website, "website", os.Getenv("CODESIGN_WEBSITE"),
		"Authenticode program URL (env CODESIGN_WEBSITE)")
	flag.StringVar(&opts.output, "output", "",
		"output path; only valid with a single input file (default: replace input in place)")
	flag.IntVar(&opts.retries, "retries", 2, "retries per file on network/gateway errors") //nolint:mnd
	flag.DurationVar(&opts.timeout, "timeout", codesign.DefaultTimeout, "per-attempt timeout")
	flag.BoolVar(&opts.health, "health", false, "check the service health and exit")
	flag.BoolVar(&opts.version, "version", false, "print the version and exit")
	flag.Parse()

	// Normalize once so the OIDC audience and the client URL are the same
	// string; a trailing slash would otherwise make the daemon reject the
	// token's audience.
	opts.url = strings.TrimSuffix(opts.url, "/")

	return opts
}

func run() error {
	opts := parseFlags()

	if opts.version {
		fmt.Println(version.Print("codesign"))

		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := buildClient(ctx, opts, !opts.health)
	if err != nil {
		return err
	}

	if opts.health {
		err = client.Health(ctx)
		if err != nil {
			return fmt.Errorf("health check: %w", err)
		}

		fmt.Println("healthy")

		return nil
	}

	return signFiles(ctx, client, opts)
}

// buildClient assembles the client, fetching a GitHub Actions OIDC token
// when one is needed, none was provided, and the Actions runtime is
// available. Health checks never need a token (/health is unauthenticated),
// so they must not require id-token permissions.
func buildClient(ctx context.Context, opts *flags, needToken bool) (*codesign.Client, error) {
	token := opts.token
	if needToken && token == "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
		if opts.url == "" {
			return nil, codesign.ErrNoURL
		}

		var err error

		token, err = codesign.FetchGitHubToken(ctx, opts.url)
		if err != nil {
			return nil, fmt.Errorf("fetching GitHub OIDC token: %w", err)
		}
	}

	client, err := codesign.New(&codesign.Config{
		URL:        opts.url,
		ClientCert: opts.cert,
		ClientKey:  opts.key,
		RootCA:     opts.rootCA,
		Token:      token,
		Retries:    opts.retries,
		Timeout:    opts.timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("building client: %w", err)
	}

	return client, nil
}

var errOneOutput = errors.New("-output requires exactly one input file")

// signFiles signs every file argument, in place unless -output is set.
func signFiles(ctx context.Context, client *codesign.Client, opts *flags) error {
	files := flag.Args()
	if len(files) == 0 {
		return errNoFiles
	}

	if opts.output != "" && len(files) != 1 {
		return errOneOutput
	}

	signOpts := &codesign.SignOptions{Name: opts.name, URL: opts.website}

	for _, file := range files {
		start := time.Now()

		err := client.SignFile(ctx, file, opts.output, signOpts)
		if err != nil {
			return fmt.Errorf("signing %s: %w", file, err)
		}

		fmt.Printf("signed %s in %s\n", file, time.Since(start).Round(time.Millisecond))
	}

	return nil
}
