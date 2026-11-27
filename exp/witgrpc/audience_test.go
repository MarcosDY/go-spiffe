package witgrpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/witgrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const echoService = "/grpc.examples.echo.Echo"

func TestExpectedAudience(t *testing.T) {
	audience, err := witgrpc.ExpectedAudience("https://server.example.org:50051")
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("accepts a proof for the configured value", func(t *testing.T) {
		require.NoError(t, audience(ctx, echoService+"/UnaryEcho",
			"https://server.example.org:50051"+echoService))
	})

	t.Run("rejects a proof for another target", func(t *testing.T) {
		err := audience(ctx, echoService+"/UnaryEcho",
			"https://elsewhere.example.org:50051"+echoService)
		require.ErrorContains(t, err, "not accepted here")
	})

	t.Run("one value covers every service and method", func(t *testing.T) {
		// Normalization discards the path, so an operator configures the
		// authority once rather than per service.
		require.NoError(t, audience(ctx, "/other.Service/Method",
			"https://server.example.org:50051/other.Service"))
	})

	t.Run("ignores the incoming metadata entirely", func(t *testing.T) {
		spoofed := metadata.NewIncomingContext(ctx,
			metadata.Pairs(":authority", "elsewhere.example.org:50051"))
		err := audience(spoofed, echoService+"/UnaryEcho",
			"https://elsewhere.example.org:50051"+echoService)
		require.ErrorContains(t, err, "not accepted here")
	})

	t.Run("rejects an invalid configuration", func(t *testing.T) {
		_, err := witgrpc.ExpectedAudience("not a uri")
		require.EqualError(t, err, `witwpt: audience "not a uri" is not an absolute http(s) URI`)
	})
}

func TestUnsafeAudienceFromContext(t *testing.T) {
	audience := witgrpc.UnsafeAudienceFromContext()

	// grpc-go's client-side createAudience builds
	//   "https://" + TrimSuffix(host, ":443") + method[:lastSlash]
	// so the reconstruction here must match that exactly.
	tests := []struct {
		name       string
		authority  string
		fullMethod string
		aud        string
		rejected   bool
	}{
		{
			name:       "reconstructs what the client computed",
			authority:  "server.example.org:50051",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "https://server.example.org:50051" + echoService,
		},
		{
			name:       "the scheme is https even though gRPC has no scheme",
			authority:  "server.example.org:50051",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "http://server.example.org:50051" + echoService,
			rejected:   true,
		},
		{
			name:       "a default port on either side normalizes away",
			authority:  "server.example.org:443",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "https://server.example.org" + echoService,
		},
		{
			name:       "a proof for another authority is rejected",
			authority:  "server.example.org:50051",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "https://victim.example.org:50051" + echoService,
			rejected:   true,
		},
		{
			name:       "a proof for another port is rejected",
			authority:  "server.example.org:50051",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "https://server.example.org:50052" + echoService,
			rejected:   true,
		},
		{
			name:       "missing authority rejects rather than matching loosely",
			authority:  "",
			fullMethod: echoService + "/UnaryEcho",
			aud:        "https://server.example.org:50051" + echoService,
			rejected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.authority != "" {
				ctx = metadata.NewIncomingContext(ctx,
					metadata.Pairs(":authority", tt.authority))
			}

			err := audience(ctx, tt.fullMethod, tt.aud)
			if tt.rejected {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAudienceIsABareFuncType(t *testing.T) {
	// The escape hatch is a type conversion, not a third constructor.
	custom := witgrpc.Audience(func(_ context.Context, fullMethod, aud string) error {
		if aud == "urn:internal:"+fullMethod {
			return nil
		}
		return errors.New("nope")
	})

	require.NoError(t, custom(context.Background(), "/svc/M", "urn:internal:/svc/M"))
	require.Error(t, custom(context.Background(), "/svc/M", "urn:internal:/other"))
}
