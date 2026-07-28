package withttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/withttp"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const serverAudience = "https://server.example.org"

// validProofClaims returns proof claims that should verify against f.
func (f *fixture) validProofClaims() map[string]any {
	return map[string]any{
		"aud": serverAudience + "/v2/orders",
		"exp": jwt.NewNumericDate(time.Now().Add(witwpt.DefaultProofLifetime)),
		"jti": "jti-middleware-0001",
		"wth": witwpt.WITThumbprint(f.svid.Marshal()),
	}
}

// serve runs the middleware over a recording handler and returns the response.
func serve(t *testing.T, f *fixture, witToken, proof string,
	opts ...withttp.ServerOption) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	var reached bool
	handler := withttp.Middleware(
		witwpt.NewVerifier(f.bundle),
		withttp.ExpectedAudience(serverAudience),
		witwpt.AuthorizeAny(),
		opts...,
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	request := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
	if witToken != "" {
		request.Header.Set(withttp.HeaderWIT, witToken)
	}
	if proof != "" {
		request.Header.Set(withttp.HeaderProof, proof)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder, reached
}

func TestMiddlewareAcceptsAValidPair(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	recorder, reached := serve(t, f, f.svid.Marshal(), proof)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.True(t, reached, "the handler must run")
}

func TestMiddlewareAnswers403ForEveryFailure(t *testing.T) {
	// One status for every stage, deliberately. Distinct codes for "malformed
	// token", "audience mismatch", and "authorizer denied" would form an oracle
	// telling a caller how far a forgery progressed. 401 is unavailable anyway:
	// workload-creds §5.2 rules out the WWW-Authenticate flow for the WIT.
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
			name:  "proof missing",
			stage: witwpt.StageProof,
			proof: func(*testing.T, *fixture) string { return "" },
		},
		{
			name:  "credential missing",
			stage: witwpt.StageWIT,
			wit:   func(*testing.T, *fixture) string { return "" },
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
				claims["wth"] = witwpt.WITThumbprint("some other token")
				return makeWPT(t, f.cnfKey, claims)
			},
		},
		{
			name:  "proof for another audience",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *fixture) string {
				claims := f.validProofClaims()
				claims["aud"] = "https://elsewhere.example.org/v2/orders"
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

			witToken := f.svid.Marshal()
			if tt.wit != nil {
				witToken = tt.wit(t, f)
			}

			// Rebuild the proof against whichever credential is being sent, so
			// only the property under test is wrong.
			claims := f.validProofClaims()
			claims["wth"] = witwpt.WITThumbprint(witToken)
			proof := makeWPT(t, f.cnfKey, claims)
			if tt.proof != nil {
				proof = tt.proof(t, f)
			}

			var handled error
			recorder, reached := serve(t, f, witToken, proof,
				withttp.WithErrorHandler(func(_ *http.Request, err error) { handled = err }))

			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.False(t, reached, "the handler must not run")
			assert.Empty(t, recorder.Body.String(), "no detail may leak to the caller")

			require.Error(t, handled, "the operator's handler must receive the reason")
			var verr *witwpt.Error
			require.ErrorAs(t, handled, &verr)
			assert.Equal(t, tt.stage, verr.Stage)
		})
	}
}

func TestMiddlewareAuthorizerDenial(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	var handled error
	var reached bool
	stranger := spiffeid.RequireFromString("spiffe://example.org/someone-else")

	handler := withttp.Middleware(
		witwpt.NewVerifier(f.bundle),
		withttp.ExpectedAudience(serverAudience),
		witwpt.AuthorizeID(stranger),
		withttp.WithErrorHandler(func(_ *http.Request, err error) { handled = err }),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	request := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
	request.Header.Set(withttp.HeaderWIT, f.svid.Marshal())
	request.Header.Set(withttp.HeaderProof, proof)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.False(t, reached)
	require.Error(t, handled)

	// Authorization failures carry no stage: the middleware ran the authorizer
	// itself and already knows which step refused.
	var verr *witwpt.Error
	assert.False(t, errors.As(handled, &verr), "an authorizer denial is not a verification stage")
}

func TestMiddlewarePlacesTheCredentialInContext(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	var (
		gotSVID *witsvid.SVID
		gotID   spiffeid.ID
	)
	handler := withttp.Middleware(
		witwpt.NewVerifier(f.bundle),
		withttp.ExpectedAudience(serverAudience),
		witwpt.AuthorizeAny(),
	)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var err error
		gotSVID, err = withttp.PeerSVIDFromContext(r.Context())
		require.NoError(t, err)
		gotID, err = withttp.PeerIDFromContext(r.Context())
		require.NoError(t, err)
	}))

	request := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
	request.Header.Set(withttp.HeaderWIT, f.svid.Marshal())
	request.Header.Set(withttp.HeaderProof, proof)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	require.NotNil(t, gotSVID, "the whole verified credential must reach the handler")
	assert.Equal(t, f.id, gotSVID.ID)
	assert.Equal(t, f.id, gotID)
	assert.Contains(t, gotSVID.Claims, "cnf")
}

func TestMiddlewareRequiresExactlyOneOfEachToken(t *testing.T) {
	// wpt-01 §2 step 1 requires exactly one proof. Reading only the first field
	// line would diverge from an intermediary that comma-joins repeated values,
	// which is the classic shape of a header-smuggling bug.
	f := newFixture(t)
	valid := makeWPT(t, f.cnfKey, f.validProofClaims())

	tests := []struct {
		name   string
		wits   []string
		proofs []string
		stage  witwpt.Stage
	}{
		{
			name:   "two proofs, the first valid",
			wits:   []string{f.svid.Marshal()},
			proofs: []string{valid, "second-value"},
			stage:  witwpt.StageProof,
		},
		{
			name:   "two credentials, the first valid",
			wits:   []string{f.svid.Marshal(), "second-value"},
			proofs: []string{valid},
			stage:  witwpt.StageWIT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handled error
			handler := withttp.Middleware(
				witwpt.NewVerifier(f.bundle),
				withttp.ExpectedAudience(serverAudience),
				witwpt.AuthorizeAny(),
				withttp.WithErrorHandler(func(_ *http.Request, err error) { handled = err }),
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler must not run")
			}))

			request := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
			for _, v := range tt.wits {
				request.Header.Add(withttp.HeaderWIT, v)
			}
			for _, v := range tt.proofs {
				request.Header.Add(withttp.HeaderProof, v)
			}

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, http.StatusForbidden, recorder.Code)
			require.Error(t, handled)
			var verr *witwpt.Error
			require.ErrorAs(t, handled, &verr)
			assert.Equal(t, tt.stage, verr.Stage)
		})
	}
}

func TestMiddlewareStripsTheTokensBeforeTheHandler(t *testing.T) {
	// A handler that proxies onward -- httputil.ReverseProxy, or any client that
	// copies inbound headers -- would otherwise forward the credential and a
	// still-valid proof verbatim, performing an onward replay by accident. The
	// verified credential is already in the context, so the raw tokens have no
	// remaining use.
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	var gotWIT, gotProof string
	var svidReachedHandler bool
	handler := withttp.Middleware(
		witwpt.NewVerifier(f.bundle),
		withttp.ExpectedAudience(serverAudience),
		witwpt.AuthorizeAny(),
	)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotWIT = r.Header.Get(withttp.HeaderWIT)
		gotProof = r.Header.Get(withttp.HeaderProof)
		_, err := withttp.PeerSVIDFromContext(r.Context())
		svidReachedHandler = err == nil
	}))

	request := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
	request.Header.Set(withttp.HeaderWIT, f.svid.Marshal())
	request.Header.Set(withttp.HeaderProof, proof)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	assert.Empty(t, gotWIT, "the credential must not reach the handler as a header")
	assert.Empty(t, gotProof, "the proof must not reach the handler as a header")
	assert.True(t, svidReachedHandler, "but the verified credential must still be available")
}

func TestPeerFromContextWithoutMiddleware(t *testing.T) {
	// A handler that was not wrapped must get an error, never a zero-value ID
	// that would read as an authenticated peer.
	_, err := withttp.PeerSVIDFromContext(t.Context())
	require.Error(t, err)

	_, err = withttp.PeerIDFromContext(t.Context())
	require.Error(t, err)
}

func TestMiddlewareRequiresASecureChannel(t *testing.T) {
	f := newFixture(t)
	proof := makeWPT(t, f.cnfKey, f.validProofClaims())

	newHandler := func(opts ...withttp.ServerOption) http.Handler {
		return withttp.Middleware(
			witwpt.NewVerifier(f.bundle),
			withttp.ExpectedAudience(serverAudience),
			witwpt.AuthorizeAny(),
			opts...,
		)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
	}

	request := func() *http.Request {
		r := httptest.NewRequest("GET", serverAudience+"/v2/orders", nil)
		r.Header.Set(withttp.HeaderWIT, f.svid.Marshal())
		r.Header.Set(withttp.HeaderProof, proof)
		r.TLS = nil // plaintext, or TLS terminated upstream -- indistinguishable
		return r
	}

	t.Run("plaintext is refused by default", func(t *testing.T) {
		// Default-on catches the real misconfiguration: a service listening in
		// plaintext while believing it authenticates WIT-SVIDs.
		recorder := httptest.NewRecorder()
		newHandler().ServeHTTP(recorder, request())
		assert.Equal(t, http.StatusForbidden, recorder.Code)
	})

	t.Run("WithTrustedTransport allows it", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		newHandler(withttp.WithTrustedTransport()).ServeHTTP(recorder, request())
		assert.Equal(t, http.StatusTeapot, recorder.Code, "the handler must run")
	})
}

// TestEndToEnd is the one place the client and server halves meet. Everything
// else pins each half against something outside itself.
func TestEndToEnd(t *testing.T) {
	f := newFixture(t)

	var peerID spiffeid.ID
	handler := withttp.Middleware(
		witwpt.NewVerifier(f.bundle, witwpt.WithReplayCache(witwpt.NewMemoryReplayCache())),
		withttp.UnsafeAudienceFromRequest(),
		witwpt.AuthorizeMemberOf(f.id.TrustDomain()),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := withttp.PeerIDFromContext(r.Context())
		require.NoError(t, err)
		peerID = id
		w.WriteHeader(http.StatusNoContent)
	}))

	server := httptest.NewTLSServer(handler)
	defer server.Close()

	client := server.Client()
	client.Transport = withttp.NewRoundTripper(staticSource{svid: f.svid}, client.Transport)

	resp, err := client.Get(server.URL + "/v2/orders")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNoContent, resp.StatusCode,
		"a client-minted proof must satisfy the server's verifier")
	assert.Equal(t, f.id, peerID)

	// A second request must also succeed: each carries its own jti, so the
	// replay cache does not reject legitimate traffic.
	resp2, err := client.Get(server.URL + "/v2/orders")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode)
}
