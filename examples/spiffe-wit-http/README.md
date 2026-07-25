# Authenticating HTTP requests with WIT-SVIDs

This example shows how to use the go-spiffe library to authenticate an HTTP client to a server using WIT-SVIDs obtained from the SPIFFE Workload API.

A WIT-SVID is not a bearer token. It names a public key in its `cnf.jwk` claim, and a workload presenting one must prove it holds the matching private key. This example uses the Workload Proof Token (WPT) protocol to do that: the client mints a short-lived second token per request, signed with the confirmation key and bound both to the credential and to the request target.

> **Note:** the packages used here live under `exp/` and are subject to breaking changes.

The scenario goes like this:
1. The server starts listening for HTTPS connections.
2. The client sends a `GET` request. Its transport attaches the WIT-SVID and a freshly minted proof.
3. The server validates the WIT-SVID against its trust bundle, verifies the proof against the key that credential names, and authorizes the SPIFFE ID.
4. The handler runs and greets the authenticated client by its SPIFFE ID.
5. The client logs the response.

Note the split of responsibilities: **TLS is the channel, not the credential.** The X.509-SVID machinery authenticates the *server* to the client and keeps the exchange confidential. The client is not authenticated at the TLS layer at all — its WIT-SVID does that, at the application layer.

## Attaching the credential
The **client workload** wraps its transport with [withttp.NewRoundTripper](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#NewRoundTripper):
```go
	client := &http.Client{
		Transport: withttp.NewRoundTripper(witSource, transport),
	}
```
Where:
- witSource is a [workloadapi.WITSource](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi#WITSource), which supplies the WIT-SVID and its private key.
- transport is the client's own `*http.Transport`, carrying the TLS configuration from [tlsconfig.TLSClientConfig](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig#TLSClientConfig). Passing the base transport rather than a `*tls.Config` keeps the TLS channel yours: `withttp` forms no opinion about timeouts, proxies, or pooling, and you can compose it with your own tracing or retry transport. Pass `nil` to use `http.DefaultTransport`.

A fresh proof is minted for every request. Nothing in the client names a header or computes a hash.

Requests over plain `http` are refused rather than sent, because both drafts require the credential to travel over a server-authenticated TLS connection. See "TLS terminated upstream" below for the escape hatch.

## Verifying the credential
The **server workload** builds a verifier once, then wraps its handler with [withttp.Middleware](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#Middleware):
```go
	verifier := witwpt.NewVerifier(witSource, witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

	handler := withttp.Middleware(
		verifier,
		withttp.ExpectedAudience(serverURI),
		witwpt.AuthorizeID(clientID),
		withttp.WithErrorHandler(func(r *http.Request, err error) {
			log.Printf("rejected %s %s: %v", r.Method, r.URL.Path, err)
		}),
	)(http.HandlerFunc(index))
```
Where:
- verifier holds the protocol settings. Build it once at startup: every listener handed the same verifier shares one replay cache, which is what you want in a process serving more than one endpoint.
- [witwpt.WithReplayCache](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witwpt#WithReplayCache) rejects a proof whose `jti` has already been seen. It is opt-in, and `NewMemoryReplayCache` protects a **single process only** — a deployment running several replicas needs a shared store to reject a proof replayed to a different replica. Implement [witwpt.ReplayCache](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witwpt#ReplayCache) over one; a Redis `SET NX EX` maps onto it directly.
- [withttp.ExpectedAudience](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#ExpectedAudience) states which target URIs this service answers to. It is a **required argument**: there is no safe default, so omitting it is a compile error rather than a silent weakening. Comparison is under normalization, so one value covers every route, and an explicit `:443` or a trailing slash still matches.
- clientID, with [witwpt.AuthorizeID](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witwpt#AuthorizeID), accepts only a peer whose WIT-SVID has that SPIFFE ID. These are the same [spiffeid.Matcher](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffeid#Matcher) functions the X.509 path uses, so an authorizer you wrote for `tlsconfig` works here.
- [withttp.WithErrorHandler](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#WithErrorHandler) is how you see *why* a request was refused. The caller is told only that it was refused.

Inside the handler, the verified peer is available from the request context:
```go
	id, err := withttp.PeerIDFromContext(r.Context())
```
[withttp.PeerSVIDFromContext](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#PeerSVIDFromContext) returns the whole credential, including any claims the issuer put on it.

## Every rejection is 403
Whatever goes wrong — a malformed token, a proof for another audience, an expired credential, a denied authorization — the caller gets `403 Forbidden` with an empty body. That is deliberate: distinct status codes per failure would tell a caller how far a forgery got. The detail goes to your error handler instead, and verification failures carry a machine-readable stage:
```go
	var verr *witwpt.Error
	if errors.As(err, &verr) {
		metrics.Inc("wit_auth_rejected", verr.Stage.String())  // "wit", "proof", or "replay"
	}
```
`401` is not an option here regardless: it obliges a `WWW-Authenticate` challenge and a follow-up `Authorization` header, and the WIT-SVID specification rules that flow out.

## Choosing the audience behind a proxy
`ExpectedAudience` is the recommended mode, and the one this example uses. The alternative, [withttp.UnsafeAudienceFromRequest](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/withttp#UnsafeAudienceFromRequest), needs no configuration but **does not protect against onward replay** — it is named `Unsafe` because it reads `r.Host`, which `wpt-01` §3.1 says a validator "MUST NOT use". Prefer `ExpectedAudience`; the difference matters most when a proxy is involved.

Both modes verify proof of possession identically. What differs is whether a legitimate receiver can reuse your credential against a third party:

```text
1. Client C -> service A     Host: a.example.org
   A verifies successfully, and now holds a valid, unexpired pair for C.

2. A replays both tokens -> service B,  setting  Host: a.example.org

   under ExpectedAudience("https://b.example.org")  ->  audience mismatch, REJECTED
   under UnsafeAudienceFromRequest()                      ->  B derives "https://a.example.org",
                                                        which matches, ACCEPTED --
                                                        B now believes it is talking to C
```

A forges nothing; the proof is genuine, it just was not meant for B. The only thing A supplies is a `Host` header, which any client sets freely. This is what the WPT draft means by "MUST NOT use untrusted information obtained from the request to determine if the hostname belongs to an authorized authority."

**Behind a reverse proxy, configure the audience the client dials.** If clients reach you at `https://api.example.org` but the proxy forwards to `https://backend.internal:8443`, the proof's audience is the *former*, so that is what the backend must expect:
```go
	withttp.ExpectedAudience("https://api.example.org")
```
Pass several values if the service is reachable under more than one name. A mismatch names both the expected and received values in the error handler, so this is diagnosable from a log line.

Note the proxy topology in [`examples/spiffe-jwt-using-proxy`](../spiffe-jwt-using-proxy) needs no change on this front: that proxy opens a *fresh* TLS connection to its backend, so the backend still sees TLS.

## TLS terminated upstream
The server cannot tell plaintext apart from TLS-terminated-by-a-sidecar: both arrive with `r.TLS == nil`. So the default is to reject, and a mesh operator asserts otherwise explicitly:
```go
	withttp.Middleware(verifier, audience, authorizer, withttp.WithTrustedTransport())
```
The same option exists on the client for a plaintext loopback hop to a sidecar. The library cannot detect its misuse, so it is named for the precondition you are asserting rather than for the check it skips.

One combination to avoid: `WithTrustedTransport()` together with `UnsafeAudienceFromRequest()`. With `r.TLS` nil the derived scheme is `http`, while the client — which required `https` before attaching tokens — minted an `https` audience, so every request fails on audience. A TLS-terminating deployment wants `ExpectedAudience` with the externally visible URI, which is the same advice as the proxy section above.

## Building
To build the client workload:
```bash
cd examples/spiffe-wit-http/client
go build
```

To build the server workload:
```bash
cd examples/spiffe-wit-http/server
go build
```

## Running
**This example cannot be run end to end today.** Unlike the other examples here, it needs a SPIFFE Workload API implementation that serves the `FetchWITSVID` and `FetchWITBundles` RPCs, and no released implementation does yet. SPIRE does not.

Rather than list steps that fail at the first one, here is what a runnable setup will require:
- A Workload API implementation serving §7 of the [SPIFFE Workload API specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) (the WIT-SVID profile), reachable at `unix:///tmp/agent.sock`.
- Registration entries for `spiffe://example.org/server` and `spiffe://example.org/client`, with the client entry configured to be issued a WIT-SVID.
- The trust domain `example.org`, and the trust bundle carrying a WIT authority so the server can validate the client's credential.

The client and server code above is complete and compiles; only the credential source is missing.
