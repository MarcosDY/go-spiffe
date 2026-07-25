package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/withttp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	serverURL  = "https://localhost:8443"
	socketPath = "unix:///tmp/agent.sock"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	// Time out the example after 30 seconds. This prevents the example from hanging if the workloads are not properly registered with SPIRE.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create client options to setup expected socket path,
	// as default sources will use value from environment variable `SPIFFE_ENDPOINT_SOCKET`
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create an X509Source for the TLS channel. The WIT-SVID authenticates this
	// workload to the server; TLS is what keeps the exchange confidential and
	// authenticates the server to us.
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer x509Source.Close()

	serverID := spiffeid.RequireFromString("spiffe://example.org/server")
	transport := &http.Transport{
		TLSClientConfig: tlsconfig.TLSClientConfig(x509Source, tlsconfig.AuthorizeID(serverID)),
	}

	// Create a WITSource to fetch the WIT-SVID and its private key.
	witSource, err := workloadapi.NewWITSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create WITSource: %w", err)
	}
	defer witSource.Close()

	// Wrap the transport. From here on every request carries the WIT-SVID and a
	// freshly minted proof of possession; nothing below deals with either.
	client := &http.Client{
		Transport: withttp.NewRoundTripper(witSource, transport),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", serverURL, nil)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to issue request to %q: %w", serverURL, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}
	log.Printf("%s", body)
	return nil
}
