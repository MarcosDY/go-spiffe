package witgrpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ServerOption configures the server side of WIT authentication.
type ServerOption interface {
	configureServer(*serverConfig)
}

type serverConfig struct {
	trustedTransport bool
	onError          func(ctx context.Context, fullMethod string, err error)
}

type serverOption func(*serverConfig)

func (fn serverOption) configureServer(c *serverConfig) { fn(c) }

// WithErrorHandler registers a callback invoked with the reason an RPC was
// rejected. The status returned to the caller carries no detail, so this is the
// only way to observe an authentication failure.
//
// Verification failures are *witwpt.Error and carry a Stage suitable as a metric
// dimension. An authorization failure carries no stage, since the interceptor ran
// the authorizer itself and already knows which step refused.
func WithErrorHandler(
	handler func(ctx context.Context, fullMethod string, err error)) ServerOption {
	return serverOption(func(c *serverConfig) {
		c.onError = handler
	})
}

// UnaryServerInterceptor authenticates each unary RPC's WIT-SVID and proof
// against verifier, authorizes the peer, and places the verified credential in
// the handler's context for PeerSVIDFromContext.
//
// audience is a required argument because there is no safe default: accepting any
// audience would let a service replay onward a proof it received. Omitting it is a
// compile error rather than a silent weakening.
//
// A missing or invalid credential is answered with codes.Unauthenticated, a
// replay cache failure with codes.Unavailable, and a refusal by authorizer with
// codes.PermissionDenied. No status carries detail; register WithErrorHandler
// to see why.
func UnaryServerInterceptor(verifier *witwpt.Verifier, audience Audience,
	authorizer witwpt.Authorizer, opts ...ServerOption) grpc.UnaryServerInterceptor {
	config := newServerConfig(opts)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {
		svid, err := authenticate(ctx, info.FullMethod, verifier, audience, authorizer, config)
		if err != nil {
			return nil, err
		}
		return handler(forHandler(ctx, svid), req)
	}
}

// StreamServerInterceptor is the streaming counterpart of
// UnaryServerInterceptor.
//
// Verification runs once, when the stream opens, not per message. A long-lived
// stream therefore outlives its proof's expiry. That is inherent to the Workload
// Proof Token, which binds a request and defines no stream semantics; treat a
// stream's authentication as established at open.
func StreamServerInterceptor(verifier *witwpt.Verifier, audience Audience,
	authorizer witwpt.Authorizer, opts ...ServerOption) grpc.StreamServerInterceptor {
	config := newServerConfig(opts)

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {
		ctx := ss.Context()
		svid, err := authenticate(ctx, info.FullMethod, verifier, audience, authorizer, config)
		if err != nil {
			return err
		}
		// grpc.ServerStream.Context() is fixed at stream creation, so the
		// credential has to be carried by a wrapper for the handler to see it.
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: forHandler(ctx, svid)})
	}
}

func newServerConfig(opts []ServerOption) *serverConfig {
	config := &serverConfig{}
	for _, opt := range opts {
		opt.configureServer(config)
	}
	return config
}

// authenticate is shared by both interceptors, which are otherwise identical.
func authenticate(ctx context.Context, fullMethod string, verifier *witwpt.Verifier,
	audience Audience, authorizer witwpt.Authorizer, config *serverConfig) (*witsvid.SVID, error) {
	svid, err := verifyPeer(ctx, fullMethod, verifier, audience, config)
	if err != nil {
		if config.onError != nil {
			config.onError(ctx, fullMethod, err)
		}
		var verr *witwpt.Error
		if errors.As(err, &verr) && verr.Stage == witwpt.StageReplayCache {
			return nil, status.Error(codes.Unavailable, "unavailable")
		}
		// Matches grpc-go's own use of Unauthenticated when per-RPC credentials
		// fail its transport-security check.
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	// Authorization is a separate step from authentication: Verify answers "who is
	// this, provably", and policy is a different question. Running them as
	// distinguishable steps is what makes the status split below possible.
	if err := authorizer(svid); err != nil {
		if config.onError != nil {
			config.onError(ctx, fullMethod, wrapErr(err))
		}
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	return svid, nil
}

func verifyPeer(ctx context.Context, fullMethod string, verifier *witwpt.Verifier,
	audience Audience, config *serverConfig) (*witsvid.SVID, error) {
	// The channel is a property of the connection, not of the tokens, so it is
	// checked here rather than in the transport-neutral core.
	if err := requireSecureChannel(ctx, config); err != nil {
		return nil, err
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, wrapErr(errors.New("no metadata on the incoming RPC"))
	}

	// wpt-01 §2 step 1: exactly one of each. Taking element [0] and ignoring the
	// rest would let an RPC that an intermediary reads as a joined list be parsed
	// differently here.
	witToken, err := exactlyOne(md, MetadataKeyWIT)
	if err != nil {
		return nil, &witwpt.Error{Stage: witwpt.StageWIT, Err: err}
	}
	proofToken, err := exactlyOne(md, MetadataKeyProof)
	if err != nil {
		return nil, &witwpt.Error{Stage: witwpt.StageProof, Err: err}
	}

	// Bind this RPC into the core's transport-neutral matcher.
	matcher := witwpt.AudienceMatcher(func(aud string) error {
		return audience(ctx, fullMethod, aud)
	})

	return verifier.Verify(ctx, witToken, proofToken, matcher)
}

// exactlyOne returns the single value of a metadata key, rejecting duplication.
// An empty string is returned with no error when the key is absent, so the core
// reports the missing token with its own message.
func exactlyOne(md metadata.MD, key string) (string, error) {
	values := md.Get(key)
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("expected exactly one %q value, got %d", key, len(values))
	}
}

// forHandler returns the context to pass on: the verified credential attached,
// and the raw tokens removed from the incoming metadata.
//
// Stripping them matters because a handler that forwards incoming metadata
// onward would otherwise carry the credential and a still-valid proof with it,
// performing an onward replay by accident. Since a proof's audience is
// authority-scoped, a third party sharing the authority would accept it.
func forHandler(ctx context.Context, svid *witsvid.SVID) context.Context {
	ctx = withPeerSVID(ctx, svid)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	// Copy before deleting: the incoming MD may be shared.
	stripped := md.Copy()
	stripped.Delete(MetadataKeyWIT)
	stripped.Delete(MetadataKeyProof)
	return metadata.NewIncomingContext(ctx, stripped)
}

// requireSecureChannel rejects an RPC that did not arrive over a connection gRPC
// reports as private, unless the operator asserted otherwise.
//
// The check is on the peer's AuthInfo rather than on grpc-go's own per-RPC gate,
// because that gate lives on the client and a server cannot rely on a peer having
// run it.
//
// It deliberately does NOT use credentials.CheckSecurityLevel, which fails open:
// that helper returns nil both when the AuthInfo reports InvalidSecurityLevel and
// when it does not implement GetCommonAuthInfo at all. Since AuthInfo is an
// interface, a wrapper that embeds it hides the method and would sail through --
// so a security control built on that helper is satisfied by "some transport
// completed a handshake", which is not the question being asked here.
func requireSecureChannel(ctx context.Context, config *serverConfig) error {
	if config.trustedTransport {
		return nil
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return wrapErr(errors.New("refusing to authenticate over a non-TLS channel; " +
			"assert WithTrustedTransport if a secure channel is provided by other means"))
	}

	info, ok := p.AuthInfo.(interface {
		GetCommonAuthInfo() credentials.CommonAuthInfo
	})
	if !ok {
		return wrapErr(fmt.Errorf("transport credentials of type %T do not report a security "+
			"level, so the channel cannot be confirmed private; assert "+
			"WithTrustedTransport if a secure channel is provided by other means",
			p.AuthInfo))
	}
	if level := info.GetCommonAuthInfo().SecurityLevel; level < credentials.PrivacyAndIntegrity {
		return wrapErr(fmt.Errorf("refusing to authenticate over a channel with security "+
			"level %v; assert WithTrustedTransport if a secure channel is provided by "+
			"other means", level))
	}
	return nil
}

// wrappedStream carries a replacement context, since grpc.ServerStream.Context()
// is fixed when the stream is created.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// peerSVIDKey is unexported so no other package can place a value the accessors
// below would trust.
type peerSVIDKey struct{}

func withPeerSVID(ctx context.Context, svid *witsvid.SVID) context.Context {
	return context.WithValue(ctx, peerSVIDKey{}, svid)
}

// PeerSVIDFromContext returns the verified WIT-SVID of the peer that made the
// RPC, for a handler behind one of this package's interceptors.
//
// In a streaming handler, pass the stream's context.
//
// It returns an error when the RPC was not intercepted, rather than a zero value
// that would read as an authenticated peer.
func PeerSVIDFromContext(ctx context.Context) (*witsvid.SVID, error) {
	svid, ok := ctx.Value(peerSVIDKey{}).(*witsvid.SVID)
	if !ok || svid == nil {
		return nil, wrapErr(errors.New("no verified WIT-SVID in context"))
	}
	return svid, nil
}

// PeerIDFromContext returns the SPIFFE ID of the peer that made the RPC. It is a
// convenience over PeerSVIDFromContext for handlers that need only the identity.
func PeerIDFromContext(ctx context.Context) (spiffeid.ID, error) {
	svid, err := PeerSVIDFromContext(ctx)
	if err != nil {
		return spiffeid.ID{}, err
	}
	return svid.ID, nil
}
