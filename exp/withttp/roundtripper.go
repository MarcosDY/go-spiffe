// Package withttp authenticates net/http requests with WIT-SVIDs, using the
// Workload Proof Token protocol from exp/witwpt.
//
// A client wraps its transport with NewRoundTripper, which attaches the
// credential and a freshly minted proof to every request. A server wraps its
// handler with Middleware, which verifies both, authorizes the peer, and places
// the verified credential in the request context. Neither side's calling code
// names a header, hashes a token, or orders a verification step.
//
// The WIT-SVID and its proof must travel over a server-authenticated TLS
// connection (draft-ietf-wimse-workload-creds §9.5). That channel is the
// existing X.509 machinery in spiffetls/tlsconfig, unchanged: this package
// composes over a caller-supplied transport rather than building one.
package withttp

import (
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
)

const (
	// HeaderWIT carries the WIT-SVID's compact serialization. Registered as
	// "Workload-Identity-Token" by draft-ietf-wimse-workload-creds §5.1.1.
	//
	// Note the credential MUST NOT be sent in the Authorization header, and a
	// rejection MUST NOT be answered with 401: both would imply the bearer-token
	// semantics the WIT-SVID exists to avoid.
	HeaderWIT = "Workload-Identity-Token"

	// HeaderProof carries the Workload Proof Token's compact serialization,
	// per draft-ietf-wimse-wpt-01 §2.
	HeaderProof = "Workload-Proof-Token"
)

// ClientOption configures the client side of WIT authentication.
type ClientOption interface {
	configureClient(*clientConfig)
}

type clientConfig struct {
	trustedTransport bool
}

// WithTrustedTransport asserts that the channel is secure even though it is not
// https, and is required to attach tokens over a plaintext hop.
//
// Use it only where a secure channel is genuinely provided by other means -- a
// sidecar that terminates TLS and forwards over loopback, which is the drafts'
// "unless a secure channel is provided by some other mechanism". This package
// cannot detect its misuse, so it is named for the precondition it asserts
// rather than for the check it skips.
func WithTrustedTransport() interface {
	ClientOption
	ServerOption
} {
	return trustedTransportOption{}
}

// trustedTransportOption satisfies both option types, so one name means one
// thing on either side of the wire.
type trustedTransportOption struct{}

func (trustedTransportOption) configureClient(c *clientConfig) { c.trustedTransport = true }
func (trustedTransportOption) configureServer(c *serverConfig) { c.trustedTransport = true }

// NewRoundTripper returns an http.RoundTripper that attaches the source's
// WIT-SVID and a freshly minted proof to every request, then delegates to base.
//
// A nil base means http.DefaultTransport. Passing the base rather than a
// *tls.Config keeps the TLS channel visibly the caller's own, so this package
// forms no opinion about timeouts, proxies, or pooling, and composes with a
// tracing or retry transport.
//
// A proof is minted per request rather than cached: signing costs tens of
// microseconds, and a fresh proof keeps the replay window at its floor.
func NewRoundTripper(source witsvid.Source, base http.RoundTripper,
	opts ...ClientOption) http.RoundTripper {
	config := &clientConfig{}
	for _, opt := range opts {
		opt.configureClient(config)
	}
	return &roundTripper{source: source, base: base, config: *config}
}

type roundTripper struct {
	source witsvid.Source
	base   http.RoundTripper
	config clientConfig
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// The channel is checked before anything else, so a misconfigured client
	// fails rather than leaking a credential over plaintext.
	if req.URL.Scheme != "https" && !rt.config.trustedTransport {
		return nil, wrapErr(fmt.Errorf(
			"refusing to attach a WIT-SVID over %q; use https or assert WithTrustedTransport",
			req.URL.Scheme))
	}

	svid, err := rt.source.GetWITSVID()
	if err != nil {
		return nil, wrapErr(err)
	}

	proof, err := witwpt.Mint(svid, clientTargetURI(req))
	if err != nil {
		return nil, wrapErr(err)
	}

	// RoundTrip must not modify the request it is given.
	req = req.Clone(req.Context())
	req.Header.Set(HeaderWIT, svid.Marshal())
	req.Header.Set(HeaderProof, proof)

	return rt.transport().RoundTrip(req)
}

func (rt *roundTripper) transport() http.RoundTripper {
	if rt.base != nil {
		return rt.base
	}
	return http.DefaultTransport
}

// clientTargetURI returns the proof's aud value for an outbound request: the
// RFC 9110 target URI without query or fragment, which is the SHOULD value in
// wpt-01 §2.
//
// Unlike the server side this is a trim rather than a reconstruction, because
// req.URL is already absolute on an outbound request.
func clientTargetURI(req *http.Request) string {
	target := *req.URL
	// net/http retains URL.User for the Authorization header, so it has to be
	// cleared explicitly: otherwise a password ends up inside a signed token on
	// the wire, and in any log line reporting an audience mismatch.
	target.User = nil
	target.RawQuery = ""
	target.Fragment = ""
	target.RawFragment = ""
	return target.String()
}

func wrapErr(err error) error {
	return fmt.Errorf("withttp: %w", err)
}
