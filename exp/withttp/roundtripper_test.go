package withttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/withttp"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTripperAttachesBothTokens(t *testing.T) {
	f := newFixture(t)
	base := &capturingTransport{}
	rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base)

	request := httptest.NewRequest("GET", "https://server.example.org/v2/orders?page=2", nil)
	resp, err := rt.RoundTrip(request)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, base.got)

	t.Run("the WIT-SVID travels verbatim in its own header", func(t *testing.T) {
		assert.Equal(t, f.svid.Marshal(), base.got.Header.Get(withttp.HeaderWIT))
	})

	t.Run("neither token uses the Authorization header", func(t *testing.T) {
		// workload-creds §5.1: the WIT "is not intended for use in the
		// Authorization header".
		assert.Empty(t, base.got.Header.Get("Authorization"))
	})

	t.Run("the proof is bound to this credential and target", func(t *testing.T) {
		proof := base.got.Header.Get(withttp.HeaderProof)
		require.NotEmpty(t, proof)

		tok, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)

		var claims map[string]any
		require.NoError(t, tok.Claims(f.cnfKey.Public(), &claims))

		assert.Equal(t, witwpt.WITThumbprint(f.svid.Marshal()), claims["wth"])
		// aud is the target URI without query or fragment (wpt-01 §2).
		assert.Equal(t, "https://server.example.org/v2/orders", claims["aud"])
	})
}

func TestRoundTripperKeepsCredentialsOutOfTheAudience(t *testing.T) {
	// net/http keeps URL.User for the Authorization header, so a URL carrying
	// userinfo would otherwise put a password inside a signed token on the wire --
	// and into any log line that reports an audience mismatch.
	f := newFixture(t)
	base := &capturingTransport{}
	rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base)

	request := httptest.NewRequest("GET",
		"https://alice:s3cr3t@server.example.org/v2/orders?page=2#top", nil)
	resp, err := rt.RoundTrip(request)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	tok, err := jwt.ParseSigned(base.got.Header.Get(withttp.HeaderProof),
		[]jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, tok.Claims(f.cnfKey.Public(), &claims))

	assert.Equal(t, "https://server.example.org/v2/orders", claims["aud"])
	assert.NotContains(t, claims["aud"], "s3cr3t")
	assert.NotContains(t, claims["aud"], "alice")
}

func TestRoundTripperDoesNotMutateTheCallersRequest(t *testing.T) {
	// http.RoundTripper's contract forbids modifying the request it is given.
	f := newFixture(t)
	base := &capturingTransport{}
	rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base)

	request := httptest.NewRequest("GET", "https://server.example.org/v2/orders", nil)
	resp, err := rt.RoundTrip(request)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Empty(t, request.Header.Get(withttp.HeaderWIT),
		"the caller's request must be left untouched")
	assert.Empty(t, request.Header.Get(withttp.HeaderProof))
	assert.NotSame(t, request, base.got, "a clone should be sent")
}

func TestRoundTripperMintsAFreshProofPerRequest(t *testing.T) {
	f := newFixture(t)
	base := &capturingTransport{}
	rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base)

	proofs := make(map[string]struct{})
	for range 5 {
		request := httptest.NewRequest("GET", "https://server.example.org/v2/orders", nil)
		resp, err := rt.RoundTrip(request)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		proofs[base.got.Header.Get(withttp.HeaderProof)] = struct{}{}
	}
	assert.Len(t, proofs, 5, "each request must carry its own proof")
}

func TestRoundTripperRequiresASecureChannel(t *testing.T) {
	f := newFixture(t)

	t.Run("plaintext is refused and nothing is sent", func(t *testing.T) {
		// workload-creds §9.5 and wpt §3.1 both require a server-authenticated
		// TLS connection.
		base := &capturingTransport{}
		rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base)

		request := httptest.NewRequest("GET", "http://server.example.org/v2/orders", nil)
		resp, err := rt.RoundTrip(request) //nolint:bodyclose // no response on the error path

		require.ErrorContains(t, err, "https")
		require.Nil(t, resp)
		assert.Nil(t, base.got, "the request must not reach the wire")
	})

	t.Run("WithTrustedTransport allows a plaintext hop", func(t *testing.T) {
		base := &capturingTransport{}
		rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, base,
			withttp.WithTrustedTransport())

		request := httptest.NewRequest("GET", "http://server.example.org/v2/orders", nil)
		resp, err := rt.RoundTrip(request)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.NotNil(t, base.got)
		assert.NotEmpty(t, base.got.Header.Get(withttp.HeaderWIT))
	})
}

func TestRoundTripperPropagatesSourceFailure(t *testing.T) {
	base := &capturingTransport{}
	rt := withttp.NewRoundTripper(staticSource{err: errNoSVID}, base)

	request := httptest.NewRequest("GET", "https://server.example.org/v2/orders", nil)
	resp, err := rt.RoundTrip(request) //nolint:bodyclose // no response on the error path

	require.ErrorIs(t, err, errNoSVID)
	require.Nil(t, resp, "no response may be returned alongside an error")
	assert.Nil(t, base.got)
}

func TestRoundTripperOverRealTLS(t *testing.T) {
	// Composing over the caller's base transport is the point: the TLS channel
	// stays the existing machinery rather than something this package rebuilds.
	f := newFixture(t)

	var gotWIT string
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotWIT = r.Header.Get(withttp.HeaderWIT)
	}))
	defer server.Close()

	client := server.Client()
	client.Transport = withttp.NewRoundTripper(staticSource{svid: f.svid}, client.Transport)

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, f.svid.Marshal(), gotWIT)
}

func TestRoundTripperNilBaseUsesDefaultTransport(t *testing.T) {
	// A nil base means http.DefaultTransport. Proven by actually completing a
	// request through it rather than by inspecting a field.
	f := newFixture(t)

	var gotWIT string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotWIT = r.Header.Get(withttp.HeaderWIT)
	}))
	defer server.Close()

	// Plaintext, so the trusted-transport assertion is required here.
	rt := withttp.NewRoundTripper(staticSource{svid: f.svid}, nil, withttp.WithTrustedTransport())

	request, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(request)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, f.svid.Marshal(), gotWIT)
}
