package withttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
)

// Audience decides whether a proof's aud claim is acceptable for an incoming
// request. It is a bare func type, so a deployment-specific rule the built-in
// constructors cannot express is a type conversion rather than a new API:
//
//	withttp.Audience(func(r *http.Request, aud string) error { ... })
type Audience func(r *http.Request, aud string) error

// ExpectedAudience matches a proof against the values this service answers to,
// ignoring the incoming request. Several values may be given for a proxied or
// multi-homed deployment.
//
// This is the recommended mode. Because the expectation comes from
// configuration rather than from the request, a legitimate receiver cannot
// replay a proof it was given onward to a third party.
func ExpectedAudience(values ...string) Audience {
	// Normalized once here rather than per request.
	matcher := witwpt.AcceptAudience(values...)
	return func(_ *http.Request, aud string) error {
		return matcher(aud)
	}
}

// AudienceFromRequest matches a proof against the target URI reconstructed from
// the incoming request, which needs no configuration.
//
// It does NOT protect against onward replay. The reconstruction reads r.Host,
// which any client sets freely, so a service that verifies your proof can turn
// around and present the same pair to a third party while setting Host to its
// own name, and that third party will accept it. draft-ietf-wimse-wpt-01 §3.1
// is explicit that a validator "MUST NOT use untrusted information obtained from
// the request to determine if the hostname belongs to an authorized authority".
//
// Prefer ExpectedAudience. This mode exists for deployments where the set of
// names a service answers to is not known at configuration time, and it is
// named for the precondition it asks you to accept rather than for the check it
// skips.
func AudienceFromRequest() Audience {
	return func(r *http.Request, aud string) error {
		return witwpt.AcceptAudience(serverTargetURI(r))(aud)
	}
}

// serverTargetURI reconstructs the request's target URI.
//
// This is not the same computation the client performs. On an outbound request
// req.URL is absolute, but the stdlib fills in almost nothing on an inbound one
// -- "for most requests, fields other than Path and RawQuery will be empty" --
// so the authority has to come from r.Host (the Host header under HTTP/1.1, the
// :authority pseudo-header under HTTP/2) and the scheme from whether the
// connection was TLS.
//
// It is unexported deliberately. Both inputs are attacker-supplied or
// channel-derived rather than verified, so it must stay reachable only through
// AudienceFromRequest, whose documentation states that tradeoff. Forwarding
// headers are never consulted.
func serverTargetURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}
