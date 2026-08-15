package withttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
)

// Audience decides whether a proof's aud claim is acceptable for an incoming
// request. A rule the constructors below cannot express is a type conversion:
//
//	withttp.Audience(func(r *http.Request, aud string) error { ... })
type Audience func(r *http.Request, aud string) error

// ExpectedAudience matches a proof against the values this service answers to,
// ignoring the incoming request. Several values may be given for a proxied or
// multi-homed deployment.
//
// This is the recommended mode: because the expectation comes from configuration
// rather than from the request, a legitimate receiver cannot replay a proof it
// was given onward to a third party.
func ExpectedAudience(values ...string) Audience {
	// Normalized once here rather than per request.
	matcher := witwpt.AcceptAudience(values...)
	return func(_ *http.Request, aud string) error {
		return matcher(aud)
	}
}

// UnsafeAudienceFromRequest matches a proof against the target URI reconstructed
// from the incoming request, needing no configuration.
//
// It reads r.Host, which draft-ietf-wimse-wpt-01 §3.1 forbids: allowed URL
// authorities MUST come from a trusted source such as out-of-band configuration,
// not from the request. The consequence is that a service legitimately receiving
// a credential and proof can present the same pair onward to a third party while
// claiming this authority, and that party will accept it.
//
// Prefer ExpectedAudience, which closes this.
func UnsafeAudienceFromRequest() Audience {
	return func(r *http.Request, aud string) error {
		return witwpt.AcceptAudience(serverTargetURI(r))(aud)
	}
}

// serverTargetURI reconstructs the request's target URI. Unlike an outbound
// request, r.URL holds little more than the path, so the authority comes from
// r.Host and the scheme from whether the connection was TLS. Forwarding headers
// are never consulted.
//
// It stays unexported because both inputs are unverified; UnsafeAudienceFromRequest
// documents that tradeoff.
func serverTargetURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}
