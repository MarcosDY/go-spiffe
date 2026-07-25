package withttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/withttp"
	"github.com/stretchr/testify/require"
)

func TestExpectedAudience(t *testing.T) {
	audience := withttp.ExpectedAudience("https://server.example.org")
	request := httptest.NewRequest("GET", "https://server.example.org/v2/orders", nil)

	t.Run("accepts a proof for the configured value", func(t *testing.T) {
		require.NoError(t, audience(request, "https://server.example.org/v2/orders"))
	})

	t.Run("rejects a proof for another target", func(t *testing.T) {
		err := audience(request, "https://elsewhere.example.org/v2/orders")
		require.ErrorContains(t, err, "not accepted here")
	})

	t.Run("ignores the request entirely", func(t *testing.T) {
		// Strict mode must not consult the request, or it would inherit the
		// Host-spoofing weakness that AudienceFromRequest documents.
		spoofed := httptest.NewRequest("GET", "https://elsewhere.example.org/v2/orders", nil)
		require.ErrorContains(t,
			audience(spoofed, "https://elsewhere.example.org/v2/orders"), "not accepted here")
	})

	t.Run("accepts any of several configured values", func(t *testing.T) {
		multi := withttp.ExpectedAudience("https://a.example.org", "https://b.example.org:8443")
		require.NoError(t, multi(request, "https://b.example.org:8443/x"))
	})
}

func TestAudienceFromRequest(t *testing.T) {
	audience := withttp.AudienceFromRequest()

	tests := []struct {
		name     string
		target   string
		host     string
		headers  map[string]string
		aud      string
		rejected bool
	}{
		{
			name:   "derives scheme, authority and path from a TLS request",
			target: "https://server.example.org/v2/orders",
			aud:    "https://server.example.org/v2/orders",
		},
		{
			name:   "normalization makes the path irrelevant",
			target: "https://server.example.org/v2/orders",
			aud:    "https://server.example.org/other",
		},
		{
			name:   "preserves a non-default port",
			target: "https://server.example.org:8443/v2/orders",
			aud:    "https://server.example.org:8443/v2/orders",
		},
		{
			name:     "a proof for another host is rejected",
			target:   "https://server.example.org/v2/orders",
			aud:      "https://elsewhere.example.org/v2/orders",
			rejected: true,
		},
		{
			name:     "a proof for another port is rejected",
			target:   "https://server.example.org:8443/v2/orders",
			aud:      "https://server.example.org:9443/v2/orders",
			rejected: true,
		},
		{
			name:   "X-Forwarded-Host is never consulted",
			target: "https://server.example.org/v2/orders",
			// wpt-01 §3.1 names X-Forwarded-Host as untrusted. A proof minted
			// for the forwarded value must not be accepted.
			headers:  map[string]string{"X-Forwarded-Host": "victim.example.org"},
			aud:      "https://victim.example.org/v2/orders",
			rejected: true,
		},
		{
			name:     "X-Forwarded-Proto is never consulted",
			target:   "https://server.example.org/v2/orders",
			headers:  map[string]string{"X-Forwarded-Proto": "http"},
			aud:      "http://server.example.org/v2/orders",
			rejected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", tt.target, nil)
			for name, value := range tt.headers {
				request.Header.Set(name, value)
			}
			if tt.host != "" {
				request.Host = tt.host
			}

			err := audience(request, tt.aud)
			if tt.rejected {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAudienceFromRequestDerivesHTTPWithoutTLS(t *testing.T) {
	// Behind a TLS-terminating sidecar r.TLS is nil, so the derived scheme is
	// http while the client, which required https before attaching tokens,
	// minted an https audience. The combination therefore cannot match, which is
	// why that topology wants ExpectedAudience instead.
	audience := withttp.AudienceFromRequest()
	request := httptest.NewRequest("GET", "http://server.example.org/v2/orders", nil)
	require.Nil(t, request.TLS, "precondition: plaintext request")

	require.NoError(t, audience(request, "http://server.example.org/v2/orders"))
	require.Error(t, audience(request, "https://server.example.org/v2/orders"))
}

func TestAudienceIsABareFuncType(t *testing.T) {
	// The escape hatch is a type conversion, not a third constructor, so a
	// deployment-specific rule needs nothing new from this package.
	custom := withttp.Audience(func(r *http.Request, aud string) error {
		if aud == "urn:internal:"+r.Host {
			return nil
		}
		return errors.New("nope")
	})

	request := httptest.NewRequest("GET", "https://server.example.org/v2/orders", nil)
	require.NoError(t, custom(request, "urn:internal:server.example.org"))
	require.Error(t, custom(request, "urn:internal:other"))
}
