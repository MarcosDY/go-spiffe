package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/spiffe/go-spiffe/v2/exp/witgrpc"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

const (
	serverAddress = "localhost:50051"

	// The authority clients dial, which is what their proofs are scoped to.
	serverAudience = "https://localhost:50051"

	// Workload API socket path
	socketPath = "unix:///tmp/agent.sock"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create an X509Source to present this server's certificate. Clients are not
	// authenticated at the TLS layer here -- their WIT-SVID does that.
	source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer source.Close()

	// Create a WITSource, which supplies the trust bundle used to validate
	// incoming WIT-SVIDs.
	witSource, err := workloadapi.NewWITSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create WITSource: %w", err)
	}
	defer witSource.Close()

	// Build the verifier once. Protocol settings live here, so both interceptors
	// below share one replay cache.
	verifier := witwpt.NewVerifier(witSource, witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

	clientID := spiffeid.RequireFromString("spiffe://example.org/client")
	audience, err := witgrpc.ExpectedAudience(serverAudience)
	if err != nil {
		return fmt.Errorf("invalid audience: %w", err)
	}
	authorizer := witwpt.AuthorizeID(clientID)
	onError := witgrpc.WithErrorHandler(func(_ context.Context, fullMethod string, err error) {
		log.Printf("rejected %s: %v", fullMethod, err)
	})

	// By the time a handler runs, the peer's credential has been validated, its
	// possession of the confirmation key proven, and its identity authorized.
	server := grpc.NewServer(
		grpc.Creds(grpccredentials.TLSServerCredentials(source)),
		grpc.UnaryInterceptor(witgrpc.UnaryServerInterceptor(verifier, audience, authorizer, onError)),
		grpc.StreamInterceptor(witgrpc.StreamServerInterceptor(verifier, audience, authorizer, onError)),
	)
	pb.RegisterGreeterServer(server, &greeterServer{})

	listener, err := net.Listen("tcp", serverAddress)
	if err != nil {
		return fmt.Errorf("unable to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("listening on %s", serverAddress)
	if err := server.Serve(listener); err != nil {
		return fmt.Errorf("error serving: %w", err)
	}
	return nil
}

type greeterServer struct {
	pb.UnimplementedGreeterServer
}

func (s *greeterServer) SayHello(ctx context.Context,
	in *pb.HelloRequest) (*pb.HelloReply, error) {
	id, err := witgrpc.PeerIDFromContext(ctx)
	if err != nil {
		// Unreachable behind the interceptor, which rejects before the handler runs.
		return nil, err
	}
	return &pb.HelloReply{Message: fmt.Sprintf("Hello %s, from %s!", in.GetName(), id)}, nil
}
