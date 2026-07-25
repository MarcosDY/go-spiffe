package witwpt

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Authorizer decides whether an authenticated peer may proceed. It runs after
// verification has succeeded, so the SVID it receives is one whose proof of
// possession was checked against the trust bundle.
//
// It takes the whole credential rather than a bare SPIFFE ID, so an authorizer
// can read issuer-supplied claims, and so the signature stays transport neutral
// and can gain fields without a breaking change.
type Authorizer func(svid *witsvid.SVID) error

// AuthorizeAny allows any authenticated peer.
func AuthorizeAny() Authorizer {
	return AdaptMatcher(spiffeid.MatchAny())
}

// AuthorizeID allows a specific SPIFFE ID.
func AuthorizeID(allowed spiffeid.ID) Authorizer {
	return AdaptMatcher(spiffeid.MatchID(allowed))
}

// AuthorizeOneOf allows any SPIFFE ID in the given list of IDs.
func AuthorizeOneOf(allowed ...spiffeid.ID) Authorizer {
	return AdaptMatcher(spiffeid.MatchOneOf(allowed...))
}

// AuthorizeMemberOf allows any SPIFFE ID in the given trust domain.
func AuthorizeMemberOf(allowed spiffeid.TrustDomain) Authorizer {
	return AdaptMatcher(spiffeid.MatchMemberOf(allowed))
}

// AdaptMatcher adapts any spiffeid.Matcher for use as an Authorizer, which
// authorizes on the SPIFFE ID alone and ignores the rest of the credential.
//
// This is the same adaptation tlsconfig offers for the X.509 path, so a matcher
// written for one works unchanged with the other.
func AdaptMatcher(matcher spiffeid.Matcher) Authorizer {
	return Authorizer(func(svid *witsvid.SVID) error {
		if svid == nil {
			return errors.New("no WIT-SVID to authorize")
		}
		return matcher(svid.ID)
	})
}
