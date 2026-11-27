package witgrpc_test

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/witgrpc"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// grpcAudience is what grpc-go's createAudience hands to GetRequestMetadata.
const grpcAudience = "https://server.example.org:50051" + echoService

func TestPerRPCCredentialsCarriesBothTokens(t *testing.T) {
	f := newFixture(t)
	creds := witgrpc.NewPerRPCCredentials(staticSource{svid: f.svid})

	md, err := creds.GetRequestMetadata(context.Background(), grpcAudience)
	require.NoError(t, err)

	t.Run("keys are lowercase, mirroring the HTTP header names", func(t *testing.T) {
		// grpc-go lowercases keys on the way out regardless; using lowercase
		// here keeps what we return identical to what goes on the wire.
		assert.Contains(t, md, witgrpc.MetadataKeyWIT)
		assert.Contains(t, md, witgrpc.MetadataKeyProof)
		assert.Equal(t, "workload-identity-token", witgrpc.MetadataKeyWIT)
		assert.Equal(t, "workload-proof-token", witgrpc.MetadataKeyProof)
	})

	t.Run("the credential travels verbatim", func(t *testing.T) {
		assert.Equal(t, f.svid.Marshal(), md[witgrpc.MetadataKeyWIT])
	})

	t.Run("the proof is bound to this credential and to grpc-go's audience", func(t *testing.T) {
		tok, err := jwt.ParseSigned(md[witgrpc.MetadataKeyProof],
			[]jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)

		var claims map[string]any
		require.NoError(t, tok.Claims(f.cnfKey.Public(), &claims))

		assert.Equal(t, witwpt.WITHash(f.svid.Marshal()), claims["wth"])
		// Minted against uri[0] directly: grpc-go already computed it, so there
		// is no bespoke target derivation on the client.
		assert.Equal(t, grpcAudience, claims["aud"])
	})
}

func TestPerRPCCredentialsMintsAFreshProofPerCall(t *testing.T) {
	f := newFixture(t)
	creds := witgrpc.NewPerRPCCredentials(staticSource{svid: f.svid})

	proofs := make(map[string]struct{})
	for range 5 {
		md, err := creds.GetRequestMetadata(context.Background(), grpcAudience)
		require.NoError(t, err)
		proofs[md[witgrpc.MetadataKeyProof]] = struct{}{}
	}
	assert.Len(t, proofs, 5, "each call must carry its own proof")
}

func TestPerRPCCredentialsRequireTransportSecurity(t *testing.T) {
	f := newFixture(t)

	t.Run("true by default", func(t *testing.T) {
		creds := witgrpc.NewPerRPCCredentials(staticSource{svid: f.svid})
		assert.True(t, creds.RequireTransportSecurity())
	})

	t.Run("false when the operator asserts a trusted transport", func(t *testing.T) {
		creds := witgrpc.NewPerRPCCredentials(staticSource{svid: f.svid},
			witgrpc.WithTrustedTransport())
		assert.False(t, creds.RequireTransportSecurity())
	})
}

func TestPerRPCCredentialsRejectsMissingAudience(t *testing.T) {
	f := newFixture(t)
	creds := witgrpc.NewPerRPCCredentials(staticSource{svid: f.svid})

	// grpc-go always supplies one, but a hand-rolled caller might not, and
	// minting a proof with no audience would produce an unscoped credential.
	_, err := creds.GetRequestMetadata(context.Background())
	require.ErrorContains(t, err, "audience")
}

func TestPerRPCCredentialsPropagatesSourceFailure(t *testing.T) {
	creds := witgrpc.NewPerRPCCredentials(staticSource{err: errNoSVID})

	_, err := creds.GetRequestMetadata(context.Background(), grpcAudience)
	require.ErrorIs(t, err, errNoSVID)
}
