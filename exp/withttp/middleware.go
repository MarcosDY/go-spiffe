package withttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ServerOption configures the server side of WIT authentication.
type ServerOption interface {
	configureServer(*serverConfig)
}

type serverConfig struct {
	trustedTransport bool
	onError          func(*http.Request, error)
}

type serverOption func(*serverConfig)

func (fn serverOption) configureServer(c *serverConfig) { fn(c) }

// WithErrorHandler registers a callback invoked with the reason a request was
// rejected. The caller is told only that it was refused, so this is the only way
// to observe an authentication failure.
//
// Verification failures are *witwpt.Error and carry a Stage, which is suitable
// as a metric dimension:
//
//	withttp.WithErrorHandler(func(r *http.Request, err error) {
//	    var verr *witwpt.Error
//	    if errors.As(err, &verr) {
//	        metrics.Inc("wit_auth_rejected", verr.Stage.String())
//	    }
//	})
//
// An authorization failure carries no stage, since the middleware ran the
// authorizer itself and already knows which step refused.
func WithErrorHandler(handler func(r *http.Request, err error)) ServerOption {
	return serverOption(func(c *serverConfig) {
		c.onError = handler
	})
}

// Middleware returns a decorator that authenticates each request's WIT-SVID and
// proof against verifier, authorizes the peer, and places the verified
// credential in the request context for PeerSVIDFromContext.
//
// audience is a required argument because there is no safe default: accepting
// any audience would let a service replay a proof it received onward to this
// one. Omitting it is a compile error rather than a silent weakening.
//
// Every rejection is answered with 403 and an empty body. Distinct codes per
// failure would form an oracle telling a caller how far a forgery progressed,
// and 401 is unavailable regardless -- draft-ietf-wimse-workload-creds §5.2
// rules out the WWW-Authenticate challenge flow for the WIT. Register
// WithErrorHandler to see why a request was refused.
//
// By default a request arriving over a channel that is not TLS is rejected
// before any token work; see WithTrustedTransport.
func Middleware(verifier *witwpt.Verifier, audience Audience, authorizer witwpt.Authorizer,
	opts ...ServerOption) func(http.Handler) http.Handler {
	config := &serverConfig{}
	for _, opt := range opts {
		opt.configureServer(config)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			svid, err := authenticate(r, verifier, audience, authorizer, config)
			if err != nil {
				if config.onError != nil {
					config.onError(r, err)
				}
				// Uniform, detail-free rejection.
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, forHandler(r, svid))
		})
	}
}

// exactlyOne returns the single value of a header, rejecting both absence and
// duplication. An empty string is returned with no error when the header is
// absent, so the core reports the missing token with its own message.
func exactlyOne(r *http.Request, name string) (string, error) {
	values := r.Header.Values(name)
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("expected exactly one %s header, got %d", name, len(values))
	}
}

// forHandler returns the request to pass on: the verified credential in the
// context, and the raw tokens removed.
//
// Stripping them matters because a handler that proxies onward -- httputil.
// ReverseProxy, or any client copying inbound headers -- would otherwise forward
// the credential and a still-valid proof verbatim, performing an onward replay by
// accident. Since a proof's audience is authority-scoped, a third party sharing
// the authority would accept it. Nothing needs the raw tokens once verification
// has produced the SVID.
func forHandler(r *http.Request, svid *witsvid.SVID) *http.Request {
	// Clone so the caller's request is left as it was.
	out := r.Clone(withPeerSVID(r.Context(), svid))
	out.Header.Del(HeaderWIT)
	out.Header.Del(HeaderProof)
	return out
}

func authenticate(r *http.Request, verifier *witwpt.Verifier, audience Audience,
	authorizer witwpt.Authorizer, config *serverConfig) (*witsvid.SVID, error) {
	// The channel is a property of the connection, not of the tokens, so it is
	// checked here rather than in the transport-neutral core. r.TLS == nil covers
	// both plaintext and TLS-terminated-upstream, which are indistinguishable
	// from here -- hence the explicit opt-out rather than a guess.
	if r.TLS == nil && !config.trustedTransport {
		return nil, wrapErr(errors.New(
			"refusing to authenticate over a non-TLS channel; assert WithTrustedTransport " +
				"if a secure channel is provided by other means"))
	}

	// wpt-01 §2 step 1: exactly one of each. Taking only the first field line
	// would let a request that an intermediary reads as a comma-joined list be
	// parsed differently here, which is how header smuggling gets in.
	witToken, err := exactlyOne(r, HeaderWIT)
	if err != nil {
		return nil, &witwpt.Error{Stage: witwpt.StageWIT, Err: err}
	}
	proofToken, err := exactlyOne(r, HeaderProof)
	if err != nil {
		return nil, &witwpt.Error{Stage: witwpt.StageProof, Err: err}
	}

	// Bind this request into the core's transport-neutral matcher.
	matcher := witwpt.AudienceMatcher(func(aud string) error {
		return audience(r, aud)
	})

	svid, err := verifier.Verify(r.Context(), witToken, proofToken, matcher)
	if err != nil {
		return nil, err
	}

	// Authorization is a separate step from authentication: Verify answers "who
	// is this, provably", and policy is a different question.
	if err := authorizer(svid); err != nil {
		return nil, wrapErr(err)
	}
	return svid, nil
}

// peerSVIDKey is unexported so no other package can place a value the accessors
// below would trust.
type peerSVIDKey struct{}

func withPeerSVID(ctx context.Context, svid *witsvid.SVID) context.Context {
	return context.WithValue(ctx, peerSVIDKey{}, svid)
}

// PeerSVIDFromContext returns the verified WIT-SVID of the peer that made the
// request, for a handler wrapped by Middleware.
//
// It returns an error when the handler was not wrapped, rather than a zero value
// that would read as an authenticated peer.
func PeerSVIDFromContext(ctx context.Context) (*witsvid.SVID, error) {
	svid, ok := ctx.Value(peerSVIDKey{}).(*witsvid.SVID)
	if !ok || svid == nil {
		return nil, wrapErr(errors.New("no verified WIT-SVID in context"))
	}
	return svid, nil
}

// PeerIDFromContext returns the SPIFFE ID of the peer that made the request. It
// is a convenience over PeerSVIDFromContext for handlers that need only the
// identity.
func PeerIDFromContext(ctx context.Context) (spiffeid.ID, error) {
	svid, err := PeerSVIDFromContext(ctx)
	if err != nil {
		return spiffeid.ID{}, err
	}
	return svid.ID, nil
}
