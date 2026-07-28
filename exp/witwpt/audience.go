package witwpt

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// AudienceMatcher decides whether a WPT's aud claim is acceptable for this
// request. It is called with the aud claim exactly as it appeared in the proof.
type AudienceMatcher func(aud string) error

// AcceptAudience returns an AudienceMatcher that matches aud against values,
// normalizing both sides to scheme and authority.
//
// draft-ietf-wimse-wpt-01 §2 requires that aud "matches the target URI, or an
// acceptable alias or normalization thereof, of the HTTP request in which the WPT
// was received, ignoring any query and fragment parts". Normalization here
// lowercases the scheme and host, drops a port that is the default for the
// scheme, and discards the query and fragment.
//
// # Proofs are scoped to an authority, not to a resource
//
// This also discards the PATH, on both sides. The draft names query and fragment
// explicitly and leaves path handling to what counts as an "acceptable alias or
// normalization", so this is a deliberate reading rather than something the draft
// spells out. gRPC forces it in any case, since grpc-go's client-side audience is
// per-service.
//
// The consequence is a security tradeoff worth stating plainly: a proof is bound
// to an authority, not to a route or a method. Any endpoint sharing a hostname
// can present a captured pair to any other endpoint on that hostname for the
// proof's lifetime. WithReplayCache narrows that; a path in a configured value
// does NOT, because it is ignored -- ExpectedAudience("https://api.example.org/a")
// also accepts a proof minted for /b.
//
// A value that cannot be normalized is retained verbatim, so it never matches a
// normalized audience and appears in the mismatch error for diagnosis.
func AcceptAudience(values ...string) AudienceMatcher {
	accepted := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeAudience(value)
		if err != nil {
			normalized = value
		}
		accepted = append(accepted, normalized)
	}

	return func(aud string) error {
		if aud == "" {
			return wrapErr(errors.New("proof is missing the aud claim"))
		}

		normalized, err := normalizeAudience(aud)
		if err != nil {
			return wrapErr(fmt.Errorf("proof audience %q is not a valid absolute URI", aud))
		}

		for _, candidate := range accepted {
			if normalized == candidate {
				return nil
			}
		}

		// Both values are named so a proxy or port misconfiguration is
		// diagnosable from a single log line.
		return wrapErr(fmt.Errorf("proof audience %q is not accepted here (expected one of %q)",
			aud, accepted))
	}
}

// normalizeAudience reduces an absolute URI to scheme://authority, dropping the
// default port for the scheme along with any path, query, and fragment.
func normalizeAudience(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("not an absolute URI: %q", value)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("no host in %q", value)
	}

	if port := parsed.Port(); port != "" && !isDefaultPort(scheme, port) {
		host = host + ":" + port
	}
	return scheme + "://" + host, nil
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	default:
		return false
	}
}

func wrapErr(err error) error {
	return fmt.Errorf("witwpt: %w", err)
}
