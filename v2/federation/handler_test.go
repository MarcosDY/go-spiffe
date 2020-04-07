package federation_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const jwks = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}`

// TODO: it is a temporal test, I'll create a real suite, once we have `workloadapi.BundleSource` implemented
func TestHandler(t *testing.T) {
	trustDomain := spiffeid.TrustDomain{Id: "example.org"}
	//
	//trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	//require.NoError(t, err)

	// TODO: remplace with valid load
	jwksByte := []byte(jwks)
	writer := new(bytes.Buffer)
	source := &fakeSource{}

	handler := federation.Handler(trustDomain, source, logger.Writer(writer))
	server := httptest.NewServer(handler)
	defer server.Close()

	testCases := []struct {
		name       string
		response   string
		statusCode int
		log        string
		call       func(server *httptest.Server) (*http.Response, error)
	}{
		{
			name: "success x509 bundle",
			call: func(server *httptest.Server) (response *http.Response, err error) {
				source.bundles = map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					trustDomain: &spiffebundle.Bundle{MarshalResponse: jwksByte},
				}
				return http.Get(server.URL)
			},
			statusCode: http.StatusOK,
			response:   jwks,
		},
		{
			name: "invalid method",
			call: func(server *httptest.Server) (response *http.Response, err error) {
				source.bundles = map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					trustDomain: &spiffebundle.Bundle{},
				}
				return http.Post(server.URL, "application/json", strings.NewReader("test"))
			},
			statusCode: http.StatusMethodNotAllowed,
			response:   "method is not allowed\n",
		},
		{
			name: "bundle not found",
			call: func(server *httptest.Server) (response *http.Response, err error) {
				source.bundles = map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					spiffeid.TrustDomain{Id: "spiffe://test.domain2"}: &spiffebundle.Bundle{},
				}

				return http.Get(server.URL)
			},
			statusCode: http.StatusInternalServerError,
			response:   "unable to get bundle for provided trust domain \"spiffe://test.domain\"\n",
			log:        "unable to get bundle for provided trust domain \"spiffe://test.domain\": some error",
		},
		{
			name: "marshaling error",
			call: func(server *httptest.Server) (response *http.Response, err error) {
				source.bundles = map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					trustDomain: &spiffebundle.Bundle{},
				}
				return http.Get(server.URL)
			},
			statusCode: http.StatusInternalServerError,
			response:   "unable to marshal bundle for trust domain \"spiffe://test.domain\"",
			log:        "unable to marshal bundle for trust domain \"spiffe://test.domain\": some error",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			writer.Reset()

			res, err := testCase.call(server)
			require.NoError(t, err)
			defer res.Body.Close()

			actual, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			switch {
			case res.StatusCode == http.StatusOK:
				require.Equal(t, []string{"application/json"}, res.Header["Content-Type"])
				require.JSONEq(t, testCase.response, string(actual))
			default:
				require.Equal(t, testCase.statusCode, res.StatusCode)
				require.Equal(t, testCase.response, string(actual))

				if testCase.log != "" {
					require.Contains(t, writer.String(), testCase.log)
				}
			}
		})
	}
}

type fakeSource struct {
	bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (s *fakeSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	b, ok := s.bundles[trustDomain]
	if !ok {
		return nil, errors.New("bundle not found")
	}
	return b, nil
}