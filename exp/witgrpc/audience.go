package witgrpc

import (
	"context"
	"errors"
	"strings"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"google.golang.org/grpc/metadata"
)

// Audience decides whether a proof's aud claim is acceptable for an incoming
// RPC. gRPC has no single request object, so the request is presented as its two
// identifying parts: the context and the full method name.
//
// It is a bare func type, so a deployment-specific rule the built-in
// constructors cannot express is a type conversion rather than a new API:
//
//	witgrpc.Audience(func(ctx context.Context, fullMethod, aud string) error { ... })
type Audience func(ctx context.Context, fullMethod string, aud string) error

// ExpectedAudience matches a proof against the values this server answers to,
// ignoring the incoming RPC. Several values may be given for a proxied or
// multi-homed deployment.
//
// This is the recommended mode. Because the expectation comes from
// configuration rather than from the RPC, a legitimate receiver cannot replay a
// proof it was given onward to a third party.
//
// Give the authority a client dials, including the port: normalization discards
// the service path, so one value covers every service and method on the server.
//
// It returns an error if values is empty or any value is not an http(s) URI.
func ExpectedAudience(values ...string) (Audience, error) {
	matcher, err := witwpt.AcceptAudience(values...)
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, _ string, aud string) error {
		return matcher(aud)
	}, nil
}

// UnsafeAudienceFromContext matches a proof against the target reconstructed from
// the incoming RPC, which needs no configuration.
//
// # Do not use this unless you have read what it gives up
//
// draft-ietf-wimse-wpt-01 §3.1 says a validator "MUST NOT use untrusted
// information obtained from the request to determine if the hostname belongs to
// an authorized authority", and continues: "The validator MUST get the
// information about allowed URL authorities from a trusted source such as
// out-of-band configuration."
//
// This function reads the :authority pseudo-header, which the client controls. It
// therefore violates that requirement, and is named Unsafe for exactly that
// reason. The practical consequence is that a server which legitimately receives
// your credential and proof can present the same pair onward to a third party
// while claiming your authority, and that third party will accept it.
//
// Use ExpectedAudience. It is one string of configuration and it closes this.
func UnsafeAudienceFromContext() Audience {
	return func(ctx context.Context, fullMethod string, aud string) error {
		target, err := incomingTargetURI(ctx, fullMethod)
		if err != nil {
			return err
		}
		matcher, err := witwpt.AcceptAudience(target)
		if err != nil {
			return err
		}
		return matcher(aud)
	}
}

// incomingTargetURI reconstructs the audience string grpc-go's client computed.
//
// It must match createAudience in google.golang.org/grpc's HTTP/2 client
// (internal/transport/http2_client.go), which builds
//
//	"https://" + strings.TrimSuffix(host, ":443") + method[:lastIndexOf("/")]
//
// Two details of that are load-bearing and non-obvious. The scheme is a hardcoded
// "https", so it is NOT derived from whether this connection is really TLS --
// deriving it would break every proof over a Unix socket or a loopback hop, where
// the client still mints "https". And the audience is per-service rather than
// per-method, because everything after the final "/" is dropped; normalization
// discards the path anyway, so this only matters for matching byte-for-byte
// against a strict third-party verifier.
//
// This is unexported deliberately: :authority is client-supplied, so it must stay
// reachable only through UnsafeAudienceFromContext, whose documentation states that
// tradeoff.
func incomingTargetURI(ctx context.Context, fullMethod string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", wrapErr(errors.New("no metadata on the incoming RPC"))
	}

	authority := firstValue(md, ":authority")
	if authority == "" {
		// Fall back to the Host header some proxies send instead, then give up
		// rather than matching something loose.
		authority = firstValue(md, "host")
	}
	if authority == "" {
		return "", wrapErr(errors.New("no :authority on the incoming RPC, so the " +
			"target cannot be derived; configure ExpectedAudience instead"))
	}

	service := fullMethod
	if pos := strings.LastIndex(fullMethod, "/"); pos != -1 {
		service = fullMethod[:pos]
	}
	return "https://" + strings.TrimSuffix(authority, ":443") + service, nil
}

func firstValue(md metadata.MD, key string) string {
	if values := md.Get(key); len(values) > 0 {
		return values[0]
	}
	return ""
}
