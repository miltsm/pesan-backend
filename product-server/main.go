package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	product_server "services/product"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("[ERROR] %s\n", err.Error())
		return
	}
	srv := grpc.NewServer()
	product_server.RegisterProductServer(srv, newServer())
	fmt.Printf("listening to port: %d\n", *port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
	}
}

type productServer struct {
	product_server.UnimplementedProductServer
}

func newServer() *productServer {
	return &productServer{}
}

func (s *productServer) CreateNew(ctx context.Context, r *product_server.NewRequest) (*product_server.NewReply, error) {
	// TODO: store in postgres
	return &product_server.NewReply{
		NewProductId: "7ea92083-f0f5-46c3-a56f-006df0b0172a",
	}, nil
}

func (s *productServer) UploadPhotos(strm grpc.ClientStreamingServer[product_server.NewPhoto, emptypb.Empty]) error {
	// TODO: kafka uploads queue
	return status.Error(codes.Unimplemented, "wip")
}
