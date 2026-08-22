# Authenticating gRPC calls with WIT-SVIDs

This example shows how to use the go-spiffe library to authenticate a gRPC client to a server using WIT-SVIDs obtained from the SPIFFE Workload API.

A WIT-SVID is not a bearer token. It names a public key in its `cnf.jwk` claim, and a workload presenting one must prove it holds the matching private key. This example uses the Workload Proof Token (WPT) protocol to do that: the client mints a short-lived second token per call, signed with the confirmation key and bound both to the credential and to the call target.

> **Note:** the packages used here live under `exp/` and are subject to breaking changes.

> **gRPC carriage is not standardized.** The WIMSE drafts specify how a WIT-SVID travels over HTTP and say nothing about gRPC. go-spiffe defines it by lowercasing the two registered HTTP header names into metadata keys — `workload-identity-token` and `workload-proof-token` — which is the mapping an independent implementer would most likely choose. Until that is blessed, interoperability with a non-go-spiffe gRPC peer is not guaranteed.

The scenario goes like this:
1. The server starts listening for TLS gRPC connections.
2. The client calls `SayHello`. Its per-RPC credentials attach the WIT-SVID and a freshly minted proof.
3. The server validates the WIT-SVID against its trust bundle, verifies the proof against the key that credential names, and authorizes the SPIFFE ID.
4. The handler runs and greets the authenticated client by its SPIFFE ID.

Note the split: **TLS is the channel, not the credential.** The X.509-SVID machinery authenticates the *server* to the client. The client is not authenticated at the TLS layer at all — unlike [`examples/spiffe-grpc`](../spiffe-grpc), which uses mTLS — because its WIT-SVID does that at the application layer.

## Attaching the credential
The **client workload** adds per-RPC credentials to its dial options:
```go
	conn, err := grpc.NewClient("dns:///localhost:50051",
		grpc.WithTransportCredentials(
			grpccredentials.TLSClientCredentials(source, tlsconfig.AuthorizeID(serverID)),
		),
		grpc.WithPerRPCCredentials(witgrpc.NewPerRPCCredentials(witSource)),
	)
```
[witgrpc.NewPerRPCCredentials](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witgrpc#NewPerRPCCredentials) implements `credentials.PerRPCCredentials`, so gRPC applies it to **every** call, including streams, with no per-call code. A fresh proof is minted for each one.

The proof's audience needs no computation on the client: gRPC already hands `GetRequestMetadata` an audience string of the form `https://host/service`, which is exactly the target URI form the draft asks for.

## Verifying the credential
The **server workload** builds a verifier once and installs both interceptors:
```go
	verifier := witwpt.NewVerifier(witSource, witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

	audience, err := witgrpc.ExpectedAudience(serverAudience)
	if err != nil {
		return fmt.Errorf("invalid audience: %w", err)
	}
	authorizer := witwpt.AuthorizeID(clientID)

	server := grpc.NewServer(
		grpc.Creds(grpccredentials.TLSServerCredentials(source)),
		grpc.UnaryInterceptor(witgrpc.UnaryServerInterceptor(verifier, audience, authorizer, onError)),
		grpc.StreamInterceptor(witgrpc.StreamServerInterceptor(verifier, audience, authorizer, onError)),
	)
```
Where:
- verifier holds the protocol settings. Passing the *same* verifier to both interceptors is what makes them share one replay cache.
- [witgrpc.ExpectedAudience](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witgrpc#ExpectedAudience) is the authority clients dial, including the port. It is a **required argument** — there is no safe default, so omitting it is a compile error, and a value that is not an absolute http(s) URI is an error at startup. Normalization discards the service path, so one value covers every service and method.
- authorizer accepts only a peer whose WIT-SVID has the expected SPIFFE ID, using the same [spiffeid.Matcher](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffeid#Matcher) functions the X.509 path uses.

Inside a handler, the verified peer comes from the context:
```go
	id, err := witgrpc.PeerIDFromContext(ctx)
```
In a **streaming** handler, pass `stream.Context()` instead. [witgrpc.PeerSVIDFromContext](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/exp/witgrpc#PeerSVIDFromContext) returns the whole credential, including issuer-supplied claims.

## Status codes
| Situation | Code |
|---|---|
| Credential or proof missing, malformed, expired, or not bound | `codes.Unauthenticated` |
| Replay cache failed | `codes.Unavailable` |
| Verified, but the authorizer refused | `codes.PermissionDenied` |

None carries detail. Unlike the HTTP integration — which answers `403` for every credential failure so a caller cannot measure how far a forgery progressed — gRPC keeps this split because the two codes are structural rather than diagnostic, and it matches grpc-go's own use of `Unauthenticated` when per-RPC credentials fail its transport check. The reason goes to your error handler:
```go
	witgrpc.WithErrorHandler(func(ctx context.Context, fullMethod string, err error) {
		var verr *witwpt.Error
		if errors.As(err, &verr) {
			metrics.Inc("wit_auth_rejected", verr.Stage.String())  // "wit", "proof", or "replay"
		}
	})
```

## Streams are authenticated once, at open
The stream interceptor verifies when the stream is created, not per message, so a long-lived stream outlives its proof's expiry. That is inherent to the WPT, which binds a request and defines no stream semantics. If you need continuing proof on a long stream, re-establish it.

Note also that a rejection surfaces on the stream's **first use** rather than at construction — `client.BidirectionalStreamingEcho(ctx)` returns without error, and the first `Recv` returns `Unauthenticated`.

## Transport security
Both drafts require the credential to travel over a server-authenticated TLS connection, and both sides enforce that. What "secure enough" means depends on how you dial:

| Client dial credential | gRPC security level | Tokens attach? |
|---|---|---|
| `insecure.NewCredentials()` | rejected at dial time | no |
| `local.NewCredentials()` over **UDS** | `PrivacyAndIntegrity` | **yes, no option needed** |
| `local.NewCredentials()` over **loopback TCP** | `NoSecurity` | no |
| SPIFFE or any real TLS credentials | `PrivacyAndIntegrity` | yes |

So a workload talking to a sidecar over a **Unix socket already works** with no extra configuration: grpc-go grades UDS as private. The gap is the loopback-TCP sidecar — `127.0.0.1:15001`, the common Envoy shape — which grpc-go grades as `NoSecurity`. That is what the opt-out covers, and it is needed on **both** ends:
```go
	// client: makes RequireTransportSecurity() report false
	witgrpc.NewPerRPCCredentials(witSource, witgrpc.WithTrustedTransport())

	// server: allows an RPC whose connection is not private
	witgrpc.UnaryServerInterceptor(verifier, audience, authorizer, witgrpc.WithTrustedTransport())
```
`insecure.NewCredentials()` is refused by default either way, which is the misconfiguration worth catching.

One caveat on what the client-side guard actually guarantees. Reporting `RequireTransportSecurity() == true` reliably rejects `insecure.NewCredentials()`, because that is checked at dial time. The post-handshake check is weaker: grpc-go skips it when the transport's `AuthInfo` reports `InvalidSecurityLevel` or does not implement `GetCommonAuthInfo`, so it fails open.

The server-side interceptors therefore do **not** use `credentials.CheckSecurityLevel`, which inherits that fail-open behaviour. They require the peer's `AuthInfo` to report a security level *and* require it to be `PrivacyAndIntegrity`. A transport whose `AuthInfo` does not expose `GetCommonAuthInfo` is refused rather than waved through — a server cannot rely on a peer having run its own gate.

## Building
To build the client workload:
```bash
cd examples/spiffe-wit-grpc/client
go build
```

To build the server workload:
```bash
cd examples/spiffe-wit-grpc/server
go build
```

## Running
**This example cannot be run end to end today.** It needs a SPIFFE Workload API implementation that serves the `FetchWITSVID` and `FetchWITBundles` RPCs, and no released implementation does yet. SPIRE does not.

Rather than list steps that fail at the first one, here is what a runnable setup will require:
- A Workload API implementation serving §7 of the [SPIFFE Workload API specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) (the WIT-SVID profile), reachable at `unix:///tmp/agent.sock`.
- Registration entries for `spiffe://example.org/server` and `spiffe://example.org/client`, with the client entry configured to be issued a WIT-SVID.
- The trust domain `example.org`, and the trust bundle carrying a WIT authority so the server can validate the client's credential.

The client and server code above is complete and compiles; only the credential source is missing.
