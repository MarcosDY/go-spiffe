package withttp_test

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

const authorityKeyID = "authority-1"

// fixture holds a matched WIT-SVID, its trust bundle, and the confirmation key,
// so a test can act as either end of the exchange.
type fixture struct {
	bundle    *witbundle.Bundle
	svid      *witsvid.SVID
	authority *ecdsa.PrivateKey
	cnfKey    *ecdsa.PrivateKey
	id        spiffeid.ID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/client")
	authority := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)

	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority(authorityKeyID, authority.Public()))

	token := makeWIT(t, authority, authorityKeyID, id, cnfKey.Public(), time.Now().Add(time.Hour))
	svid, err := witsvid.ParseInsecure(token)
	require.NoError(t, err)
	svid.PrivateKey = cnfKey

	return &fixture{bundle: bundle, svid: svid, authority: authority, cnfKey: cnfKey, id: id}
}

// makeWIT builds a WIT-SVID signed by authority.
func makeWIT(t *testing.T, authority *ecdsa.PrivateKey, kid string, id spiffeid.ID,
	cnfPub crypto.PublicKey, exp time.Time) string {
	t.Helper()

	cnfJWK := jose.JSONWebKey{Key: cnfPub, KeyID: "cnf-1", Algorithm: string(jose.ES256)}
	cnfBytes, err := cnfJWK.MarshalJSON()
	require.NoError(t, err)
	var cnfMap map[string]any
	require.NoError(t, json.Unmarshal(cnfBytes, &cnfMap))

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: authority, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("wit+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(map[string]any{
		"sub": id.String(),
		"exp": jwt.NewNumericDate(exp),
		"iat": jwt.NewNumericDate(time.Now()),
		"cnf": map[string]any{"jwk": cnfMap},
	}).Serialize()
	require.NoError(t, err)
	return token
}

// makeWPT builds a proof token locally, with full control over its claims, so
// each verification rule can be violated in isolation. Middleware tests that
// need a *valid* pair go through NewRoundTripper instead.
// The typ header is fixed here: witwpt owns the rule that it must be wpt+jwt
// and varies it in its own tests. These tests exercise the transport.
func makeWPT(t *testing.T, key crypto.Signer, claims map[string]any) string {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithType(jose.ContentType("wpt+jwt"))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

// staticSource serves one WIT-SVID, or an error.
type staticSource struct {
	svid *witsvid.SVID
	err  error
}

func (s staticSource) GetWITSVID() (*witsvid.SVID, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.svid, nil
}

func (s staticSource) GetWITSVIDForID(spiffeid.ID) (*witsvid.SVID, error) {
	return s.GetWITSVID()
}

// capturingTransport records the request it was handed instead of sending it.
type capturingTransport struct {
	got *http.Request
}

func (c *capturingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.got = r
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Request:    r,
	}, nil
}

var errNoSVID = errors.New("no WIT-SVID available")
