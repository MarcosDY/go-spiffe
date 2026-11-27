package main

import (
	"context"
	"fmt"
	"log"

	"github.com/spiffe/go-spiffe/v2/exp/witgrpc"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

// Workload API socket path
const socketPath = "unix:///tmp/agent.sock"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create an X509Source for the TLS channel. The WIT-SVID authenticates this
	// workload to the server; TLS keeps the exchange confidential and
	// authenticates the server to us.
	source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer source.Close()

	// Create a WITSource to fetch the WIT-SVID and its private key.
	witSource, err := workloadapi.NewWITSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create WITSource: %w", err)
	}
	defer witSource.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireFromString("spiffe://example.org/server")

	// TLS authenticates the server only; the client is not authenticated at the
	// TLS layer. Adding per-RPC credentials is what authenticates this workload,
	// on every call including streams.
	conn, err := grpc.NewClient("dns:///localhost:50051",
		grpc.WithTransportCredentials(
			grpccredentials.TLSClientCredentials(source, tlsconfig.AuthorizeID(serverID)),
		),
		grpc.WithPerRPCCredentials(witgrpc.NewPerRPCCredentials(witSource)),
	)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	client := pb.NewGreeterClient(conn)
	reply, err := client.SayHello(ctx, &pb.HelloRequest{Name: "world"})
	if err != nil {
		return fmt.Errorf("failed issuing RPC to server: %w", err)
	}

	log.Print(reply.Message)
	return nil
}
