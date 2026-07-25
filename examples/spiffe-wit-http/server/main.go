package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/withttp"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	serverAddress = ":8443"
	serverURI     = "https://localhost:8443"
	socketPath    = "unix:///tmp/agent.sock"
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

	// Create an X509Source to present this server's certificate. Clients are not
	// authenticated at the TLS layer here -- their WIT-SVID does that -- so the
	// server config requires no client certificate.
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer x509Source.Close()

	// Create a WITSource, which supplies the trust bundle used to validate
	// incoming WIT-SVIDs.
	witSource, err := workloadapi.NewWITSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create WITSource: %w", err)
	}
	defer witSource.Close()

	// Build the verifier once. Protocol settings live here, so every listener
	// sharing it also shares its replay cache.
	verifier := witwpt.NewVerifier(witSource, witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

	clientID := spiffeid.RequireFromString("spiffe://example.org/client")

	// Wrap the handler. By the time it runs, the peer's credential has been
	// validated, its possession of the confirmation key proven, and its identity
	// authorized.
	handler := withttp.Middleware(
		verifier,
		withttp.ExpectedAudience(serverURI),
		witwpt.AuthorizeID(clientID),
		withttp.WithErrorHandler(func(r *http.Request, err error) {
			//nolint:gosec // G706: example code; log sanitization out of scope
			log.Printf("rejected %s %s: %v", r.Method, r.URL.Path, err)
		}),
	)(http.HandlerFunc(index))

	server := &http.Server{
		Addr:              serverAddress,
		Handler:           handler,
		TLSConfig:         tlsconfig.TLSServerConfig(x509Source),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s", serverAddress)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("error serving: %w", err)
	}
	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	id, err := withttp.PeerIDFromContext(r.Context())
	if err != nil {
		// Unreachable behind the middleware, which rejects before the handler runs.
		http.Error(w, "no authenticated peer", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Hello %s!", id)
}
