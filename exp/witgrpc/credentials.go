// Package witgrpc authenticates gRPC calls with WIT-SVIDs, using the Workload
// Proof Token protocol from exp/witwpt.
//
// A client passes NewPerRPCCredentials to grpc.WithPerRPCCredentials, which
// attaches the credential and a freshly minted proof to every call including
// streams. A server installs UnaryServerInterceptor and StreamServerInterceptor,
// which verify both, authorize the peer, and place the verified credential in the
// handler's context.
//
// # gRPC carriage is not specified
//
// The WIMSE drafts define carriage for HTTP only; gRPC is mentioned nowhere. This
// package therefore defines it, by lowercasing the two registered HTTP header
// names into metadata keys -- the mapping an independent implementer reading the
// drafts would most likely choose. Until that is standardized, interoperability
// with a non-go-spiffe gRPC peer is not guaranteed.
//
// The WIT-SVID and its proof must travel over a server-authenticated TLS
// connection (draft-ietf-wimse-workload-creds §9.5). That channel is the existing
// X.509 machinery in spiffegrpc/grpccredentials, unchanged.
package witgrpc

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"google.golang.org/grpc/credentials"
)

const (
	// MetadataKeyWIT carries the WIT-SVID's compact serialization. It is the
	// registered "Workload-Identity-Token" HTTP header name
	// (draft-ietf-wimse-workload-creds §5.1.1) lowercased, since HTTP/2 forbids
	// uppercase header names and gRPC metadata keys are normalized to lowercase.
	MetadataKeyWIT = "workload-identity-token"

	// MetadataKeyProof carries the Workload Proof Token's compact
	// serialization, from "Workload-Proof-Token" (draft-ietf-wimse-wpt-01 §2).
	MetadataKeyProof = "workload-proof-token"
)

// ClientOption configures the client side of WIT authentication.
type ClientOption interface {
	configureClient(*clientConfig)
}

type clientConfig struct {
	trustedTransport bool
}

// WithTrustedTransport asserts that the channel is secure even though gRPC does
// not consider it so, and is required to attach tokens over a plaintext hop.
//
// On the client this makes RequireTransportSecurity report false, which disables
// grpc-go's own gate. Reach for it only for a plaintext loopback hop to a sidecar
// -- typically 127.0.0.1 with credentials/local, which grpc-go grades as
// NoSecurity. Over a Unix socket no option is needed: credentials/local reports
// PrivacyAndIntegrity there, so tokens attach already.
//
// On the server it allows an RPC whose connection is not TLS.
//
// This package cannot detect its misuse, so it is named for the precondition it
// asserts rather than for the check it skips.
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

// NewPerRPCCredentials returns credentials that attach the source's WIT-SVID and
// a freshly minted proof to every call, unary and streaming alike.
//
//	conn, err := grpc.NewClient(target,
//	    grpc.WithTransportCredentials(transportCreds),
//	    grpc.WithPerRPCCredentials(witgrpc.NewPerRPCCredentials(witSource)))
//
// A proof is minted per call rather than cached: signing costs tens of
// microseconds, and a fresh proof keeps the replay window at its floor.
func NewPerRPCCredentials(source witsvid.Source,
	opts ...ClientOption) credentials.PerRPCCredentials {
	config := &clientConfig{}
	for _, opt := range opts {
		opt.configureClient(config)
	}
	return &perRPCCredentials{source: source, config: *config}
}

type perRPCCredentials struct {
	source witsvid.Source
	config clientConfig
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
//
// uri is the audience grpc-go computed for this call, which needs no adjustment
// here: its createAudience already produces
// "https://" + host-without-default-port + service-path, which is exactly the
// target URI form wpt-01 §2 asks for. Note it is per-service rather than
// per-method, because grpc-go drops everything after the final "/" -- invisible
// once a verifier normalizes.
func (c *perRPCCredentials) GetRequestMetadata(_ context.Context,
	uri ...string) (map[string]string, error) {
	if len(uri) == 0 || uri[0] == "" {
		return nil, wrapErr(errors.New("no audience supplied for this call"))
	}

	svid, err := c.source.GetWITSVID()
	if err != nil {
		return nil, wrapErr(err)
	}

	proof, err := witwpt.Mint(svid, uri[0])
	if err != nil {
		return nil, wrapErr(err)
	}

	return map[string]string{
		MetadataKeyWIT:   svid.Marshal(),
		MetadataKeyProof: proof,
	}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials.
//
// Reporting true asks grpc-go to refuse to send these credentials over a
// connection it does not consider private. That reliably rejects
// insecure.NewCredentials(), which is checked at dial time.
//
// The post-handshake check is weaker, and this is a useful guard rather than a
// guarantee: grpc-go skips it when the transport's AuthInfo reports
// InvalidSecurityLevel or does not implement GetCommonAuthInfo. The server-side
// interceptors in this package therefore do not delegate to that helper -- they
// require the AuthInfo to report a level, and require it to be
// PrivacyAndIntegrity -- because a server cannot rely on a peer having run its
// own gate.
func (c *perRPCCredentials) RequireTransportSecurity() bool {
	return !c.config.trustedTransport
}
