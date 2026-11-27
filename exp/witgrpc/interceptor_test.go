package witgrpc_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witgrpc"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/examples/features/proto/echo"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const serverAuthority = "https://server.example.org:50051"

// echoServer answers with the authenticated peer's SPIFFE ID, so a test can see
// what reached the handler.
type echoServer struct {
	echo.UnimplementedEchoServer
}

func (echoServer) UnaryEcho(ctx context.Context, _ *echo.EchoRequest) (*echo.EchoResponse, error) {
	id, err := witgrpc.PeerIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return &echo.EchoResponse{Message: id.String()}, nil
}

func (echoServer) BidirectionalStreamingEcho(
	stream echo.Echo_BidirectionalStreamingEchoServer) error {
	// Reads the ID from the stream's context, which is the piece that needs the
	// wrapped stream: grpc.ServerStream.Context() is fixed at stream creation.
	id, err := witgrpc.PeerIDFromContext(stream.Context())
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.Send(&echo.EchoResponse{Message: id.String()}); err != nil {
			return err
		}
	}
}

// validProofClaims returns proof claims that should verify against f.
func (f *fixture) validProofClaims() map[string]any {
	return map[string]any{
		"aud": serverAuthority + echoService,
		"exp": jwt.NewNumericDate(time.Now().Add(witwpt.DefaultProofLifetime)),
		"jti": "jti-grpc-0001",
		"wth": witwpt.WITHash(f.svid.Marshal()),
	}
}

// startServer runs an echo server over a real loopback connection with the
// interceptors installed, and returns a client for it.
func startServer(t *testing.T, f *fixture, authorizer witwpt.Authorizer,
	opts ...witgrpc.ServerOption) echo.EchoClient {
	t.Helper()

	verifier := witwpt.NewVerifier(f.bundle)
	audience, err := witgrpc.ExpectedAudience(serverAuthority)
	require.NoError(t, err)

	// The connection is plaintext loopback, so the channel check has to be
	// asserted away; the tokens are what is under test here.
	opts = append(opts, witgrpc.WithTrustedTransport())

	server := grpc.NewServer(
		grpc.UnaryInterceptor(witgrpc.UnaryServerInterceptor(verifier, audience, authorizer, opts...)),
		grpc.StreamInterceptor(witgrpc.StreamServerInterceptor(verifier, audience, authorizer, opts...)),
	)
	echo.RegisterEchoServer(server, echoServer{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return echo.NewEchoClient(conn)
}

// callWith invokes UnaryEcho carrying the given tokens as metadata.
func callWith(t *testing.T, client echo.EchoClient, witToken, proof string) (string, error) {
	t.Helper()

	md := metadata.MD{}
	if witToken != "" {
		md.Set(witgrpc.MetadataKeyWIT, witToken)
	}
	if proof != "" {
		md.Set(witgrpc.MetadataKeyProof, proof)
	}
	// :authority is what the audience would be derived from; ExpectedAudience
	// ignores it, and the proof's aud is what matters.
	ctx := metadata.NewOutgoingContext(t.Context(), md)

	resp, err := client.UnaryEcho(ctx, &echo.EchoRequest{Message: "hi"})
	if err != nil {
		return "", err
	}
	return resp.GetMessage(), nil
}

func TestUnaryInterceptorAcceptsAValidPair(t *testing.T) {
	f := newFixture(t)
	client := startServer(t, f, witwpt.AuthorizeAny())
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	got, err := callWith(t, client, f.svid.Marshal(), proof)
	require.NoError(t, err)
	assert.Equal(t, f.id.String(), got, "the verified identity must reach the handler")
}

func TestUnaryInterceptorAnswersUnauthenticated(t *testing.T) {
	// Unlike HTTP's uniform 403, gRPC keeps the conventional split: the code is
	// structural rather than diagnostic, and it matches grpc-go's own use of
	// Unauthenticated when per-RPC credentials fail its transport check.
	tests := []struct {
		name  string
		stage witwpt.Stage
		wit   func(*testing.T, *fixture) string
		proof func(*testing.T, *fixture) string
	}{
		{
			name:  "both tokens missing",
			stage: witwpt.StageWIT,
			wit:   func(*testing.T, *fixture) string { return "" },
			proof: func(*testing.T, *fixture) string { return "" },
		},
		{
			name:  "credential missing",
			stage: witwpt.StageWIT,
			wit:   func(*testing.T, *fixture) string { return "" },
		},
		{
			name:  "proof missing",
			stage: witwpt.StageProof,
			proof: func(*testing.T, *fixture) string { return "" },
		},
		{
			name:  "proof signed by an unrelated key",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *fixture) string {
				return makeWPT(t, test.NewEC256Key(t), f.validProofClaims())
			},
		},
		{
			name:  "proof bound to a different credential",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *fixture) string {
				claims := f.validProofClaims()
				claims["wth"] = witwpt.WITHash("some other token")
				return makeWPT(t, f.cnfKey, claims)
			},
		},
		{
			name:  "proof for another audience",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *fixture) string {
				claims := f.validProofClaims()
				claims["aud"] = "https://elsewhere.example.org:50051" + echoService
				return makeWPT(t, f.cnfKey, claims)
			},
		},
		{
			name:  "expired proof",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *fixture) string {
				claims := f.validProofClaims()
				claims["exp"] = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				return makeWPT(t, f.cnfKey, claims)
			},
		},
		{
			name:  "expired credential",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *fixture) string {
				return makeWIT(t, f.authority, authorityKeyID, f.id, f.cnfKey.Public(),
					time.Now().Add(-time.Hour))
			},
		},
		{
			name:  "credential from an untrusted authority",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *fixture) string {
				return makeWIT(t, test.NewEC256Key(t), authorityKeyID, f.id,
					f.cnfKey.Public(), time.Now().Add(time.Hour))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)

			var handled error
			client := startServer(t, f, witwpt.AuthorizeAny(),
				witgrpc.WithErrorHandler(func(_ context.Context, _ string, err error) {
					handled = err
				}))

			witToken := f.svid.Marshal()
			if tt.wit != nil {
				witToken = tt.wit(t, f)
			}

			claims := f.validProofClaims()
			claims["wth"] = witwpt.WITHash(witToken)
			proof := makeWPT(t, f.cnfKey, claims)
			if tt.proof != nil {
				proof = tt.proof(t, f)
			}

			_, err := callWith(t, client, witToken, proof)

			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))

			require.Error(t, handled, "the operator's handler must receive the reason")
			var verr *witwpt.Error
			require.ErrorAs(t, handled, &verr)
			assert.Equal(t, tt.stage, verr.Stage)
		})
	}
}

func TestUnaryInterceptorAnswersPermissionDeniedWhenAuthorizerRefuses(t *testing.T) {
	// The split is only possible because authorization runs as a distinguishable
	// step after verification, rather than inside it.
	f := newFixture(t)
	stranger := spiffeid.RequireFromString("spiffe://example.org/someone-else")

	client := startServer(t, f, witwpt.AuthorizeID(stranger))
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	_, err := callWith(t, client, f.svid.Marshal(), proof)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"a denied authorizer is not an authentication failure")
}

func TestInterceptorsRequireASecureChannel(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	// Same setup as startServer but WITHOUT the trusted-transport assertion, so
	// the plaintext loopback connection is refused.
	verifier := witwpt.NewVerifier(f.bundle)
	server := grpc.NewServer(grpc.UnaryInterceptor(witgrpc.UnaryServerInterceptor(
		verifier, expectedAudience(t), witwpt.AuthorizeAny())))
	echo.RegisterEchoServer(server, echoServer{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = callWith(t, echo.NewEchoClient(conn), f.svid.Marshal(), proof)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestStreamInterceptorCarriesTheCredentialIntoTheStreamContext(t *testing.T) {
	f := newFixture(t)
	client := startServer(t, f, witwpt.AuthorizeAny())
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	md.Set(witgrpc.MetadataKeyProof, proof)
	ctx := metadata.NewOutgoingContext(t.Context(), md)

	stream, err := client.BidirectionalStreamingEcho(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(&echo.EchoRequest{Message: "hi"}))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, f.id.String(), resp.GetMessage())
	require.NoError(t, stream.CloseSend())
}

func TestStreamInterceptorRejectsAtStreamOpen(t *testing.T) {
	f := newFixture(t)
	client := startServer(t, f, witwpt.AuthorizeAny())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	// No proof.
	ctx := metadata.NewOutgoingContext(t.Context(), md)

	stream, err := client.BidirectionalStreamingEcho(ctx)
	require.NoError(t, err, "the error surfaces on first use, not at construction")

	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptorStripsTheTokensBeforeTheHandler(t *testing.T) {
	// As on the HTTP side: a handler that forwards incoming metadata onward would
	// otherwise replay the credential and a live proof by accident.
	f := newFixture(t)

	var sawTokens bool
	interceptor := witgrpc.UnaryServerInterceptor(witwpt.NewVerifier(f.bundle),
		expectedAudience(t), witwpt.AuthorizeAny(),
		witgrpc.WithTrustedTransport())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	md.Set(witgrpc.MetadataKeyProof, makeWPT(t, f.cnfKey, f.validProofClaims()))
	ctx := metadata.NewIncomingContext(t.Context(), md)

	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: echoService + "/UnaryEcho"},
		func(handlerCtx context.Context, _ any) (any, error) {
			inbound, _ := metadata.FromIncomingContext(handlerCtx)
			sawTokens = len(inbound.Get(witgrpc.MetadataKeyWIT)) > 0 ||
				len(inbound.Get(witgrpc.MetadataKeyProof)) > 0
			_, svidErr := witgrpc.PeerSVIDFromContext(handlerCtx)
			require.NoError(t, svidErr, "the verified credential must still be available")
			return nil, nil
		})

	require.NoError(t, err)
	assert.False(t, sawTokens, "the raw tokens must not reach the handler")
}

func TestInterceptorAnswersUnavailableWhenTheReplayCacheFails(t *testing.T) {
	f := newFixture(t)
	verifier := witwpt.NewVerifier(f.bundle,
		witwpt.WithReplayCache(failingCache{err: errors.New("connection refused")}))
	interceptor := witgrpc.UnaryServerInterceptor(verifier, expectedAudience(t),
		witwpt.AuthorizeAny(), witgrpc.WithTrustedTransport())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	md.Set(witgrpc.MetadataKeyProof, makeWPT(t, f.cnfKey, f.validProofClaims()))
	ctx := metadata.NewIncomingContext(t.Context(), md)

	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: echoService + "/UnaryEcho"},
		func(context.Context, any) (any, error) {
			t.Error("handler must not run")
			return nil, nil
		})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestInterceptorRequiresExactlyOneOfEachToken(t *testing.T) {
	// wpt-01 §2 step 1 requires exactly one proof. Taking element [0] and
	// ignoring extras diverges from an intermediary that joins repeated values.
	f := newFixture(t)
	client := startServer(t, f, witwpt.AuthorizeAny())
	valid := makeWPT(t, f.cnfKey, f.validProofClaims())

	tests := []struct {
		name   string
		wits   []string
		proofs []string
	}{
		{
			name:   "two proofs, the first valid",
			wits:   []string{f.svid.Marshal()},
			proofs: []string{valid, "second-value"},
		},
		{
			name:   "two credentials, the first valid",
			wits:   []string{f.svid.Marshal(), "second-value"},
			proofs: []string{valid},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.MD{}
			md.Set(witgrpc.MetadataKeyWIT, tt.wits...)
			md.Set(witgrpc.MetadataKeyProof, tt.proofs...)
			ctx := metadata.NewOutgoingContext(t.Context(), md)

			_, err := client.UnaryEcho(ctx, &echo.EchoRequest{Message: "hi"})
			require.Error(t, err, "a duplicated token must be rejected")
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestInterceptorRejectsAChannelThatIsNotPrivate(t *testing.T) {
	// The whole point of the server-side check is that it cannot rely on the peer
	// having run its own gate, so a transport reporting a low security level must
	// be refused even though grpc-go's own CheckSecurityLevel helper fails open.
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	verifier := witwpt.NewVerifier(f.bundle)
	interceptor := witgrpc.UnaryServerInterceptor(verifier,
		expectedAudience(t), witwpt.AuthorizeAny())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	md.Set(witgrpc.MetadataKeyProof, proof)
	ctx := metadata.NewIncomingContext(t.Context(), md)

	for _, tt := range []struct {
		name     string
		authInfo credentials.AuthInfo
	}{
		{name: "no auth info at all", authInfo: nil},
		{name: "reports NoSecurity", authInfo: fakeAuthInfo{level: credentials.NoSecurity}},
		{name: "reports IntegrityOnly", authInfo: fakeAuthInfo{level: credentials.IntegrityOnly}},
		{
			name: "hides its security level behind the AuthInfo interface",
			// The shape spiffegrpc/grpccredentials used to produce: a wrapper that
			// embeds the interface, so GetCommonAuthInfo is not promoted and
			// grpc-go's helper silently passes it.
			authInfo: opaqueAuthInfo{AuthInfo: fakeAuthInfo{level: credentials.NoSecurity}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peerCtx := peer.NewContext(ctx, &peer.Peer{AuthInfo: tt.authInfo})
			_, err := interceptor(peerCtx, nil,
				&grpc.UnaryServerInfo{FullMethod: echoService + "/UnaryEcho"},
				func(context.Context, any) (any, error) {
					t.Error("the handler must not run")
					return nil, nil
				})
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestInterceptorAcceptsAPrivateChannel(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	interceptor := witgrpc.UnaryServerInterceptor(witwpt.NewVerifier(f.bundle),
		expectedAudience(t), witwpt.AuthorizeAny())

	md := metadata.MD{}
	md.Set(witgrpc.MetadataKeyWIT, f.svid.Marshal())
	md.Set(witgrpc.MetadataKeyProof, proof)
	ctx := peer.NewContext(metadata.NewIncomingContext(t.Context(), md),
		&peer.Peer{AuthInfo: fakeAuthInfo{level: credentials.PrivacyAndIntegrity}})

	var reached bool
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: echoService + "/UnaryEcho"},
		func(context.Context, any) (any, error) {
			reached = true
			return nil, nil
		})
	require.NoError(t, err)
	assert.True(t, reached)
}

// fakeAuthInfo reports a security level through CommonAuthInfo, the way a
// well-behaved TransportCredentials implementation does.
type fakeAuthInfo struct {
	level credentials.SecurityLevel
}

func (fakeAuthInfo) AuthType() string { return "fake" }

func (f fakeAuthInfo) GetCommonAuthInfo() credentials.CommonAuthInfo {
	return credentials.CommonAuthInfo{SecurityLevel: f.level}
}

// opaqueAuthInfo embeds the AuthInfo interface, so GetCommonAuthInfo is hidden
// even when the wrapped value has it.
type opaqueAuthInfo struct {
	credentials.AuthInfo
}

func TestPeerFromContextWithoutInterceptor(t *testing.T) {
	// A handler that was not intercepted must get an error, never a zero-value ID
	// that would read as an authenticated peer.
	_, err := witgrpc.PeerSVIDFromContext(t.Context())
	require.Error(t, err)

	_, err = witgrpc.PeerIDFromContext(t.Context())
	require.Error(t, err)
}

// TestEndToEnd is the one place the client and server halves meet.
func TestEndToEnd(t *testing.T) {
	f := newFixture(t)

	verifier := witwpt.NewVerifier(f.bundle,
		witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

	server := grpc.NewServer(
		grpc.UnaryInterceptor(witgrpc.UnaryServerInterceptor(verifier,
			// Permissive mode, so the audience the client minted is reconstructed
			// from the RPC rather than configured.
			witgrpc.UnsafeAudienceFromContext(), witwpt.AuthorizeMemberOf(f.id.TrustDomain()),
			witgrpc.WithTrustedTransport())),
	)
	echo.RegisterEchoServer(server, echoServer{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(witgrpc.NewPerRPCCredentials(
			staticSource{svid: f.svid}, witgrpc.WithTrustedTransport())))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	client := echo.NewEchoClient(conn)

	resp, err := client.UnaryEcho(t.Context(), &echo.EchoRequest{Message: "hi"})
	require.NoError(t, err, "a client-minted proof must satisfy the server's verifier")
	assert.Equal(t, f.id.String(), resp.GetMessage())

	// A second call must also succeed: each carries its own jti.
	resp2, err := client.UnaryEcho(t.Context(), &echo.EchoRequest{Message: "again"})
	require.NoError(t, err)
	assert.Equal(t, f.id.String(), resp2.GetMessage())
}

var _ witsvid.Source = staticSource{}

func expectedAudience(t *testing.T) witgrpc.Audience {
	t.Helper()
	audience, err := witgrpc.ExpectedAudience(serverAuthority)
	require.NoError(t, err)
	return audience
}

type failingCache struct{ err error }

func (c failingCache) CheckAndRecord(context.Context, spiffeid.ID, string, time.Time) error {
	return c.err
}
