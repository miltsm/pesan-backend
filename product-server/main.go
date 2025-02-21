package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	product_server "product-server/product/go"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		log.Fatalf("[WARN] %s", err.Error())
		port = 50051
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[ERROR] %s\n", err.Error())
		return
	}
	srv := grpc.NewServer()
	product_server.RegisterProductServer(srv, newServer())
	fmt.Printf("listening to port: %d..\n", port)
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
