// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.3
// source: pesan.proto

package pesan_backend

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Pesan_Onboard_FullMethodName             = "/pesan.Pesan/Onboard"
	Pesan_RegisterPublicKey_FullMethodName   = "/pesan.Pesan/RegisterPublicKey"
	Pesan_CreateNewProduct_FullMethodName    = "/pesan.Pesan/CreateNewProduct"
	Pesan_UploadProductPhotos_FullMethodName = "/pesan.Pesan/UploadProductPhotos"
)

// PesanClient is the client API for Pesan service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PesanClient interface {
	Onboard(ctx context.Context, in *CredentialRequest, opts ...grpc.CallOption) (*ChallengeReply, error)
	RegisterPublicKey(ctx context.Context, in *AssertRequest, opts ...grpc.CallOption) (*AssertReply, error)
	CreateNewProduct(ctx context.Context, in *NewProductRequest, opts ...grpc.CallOption) (*NewProductReply, error)
	UploadProductPhotos(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[NewPhoto, emptypb.Empty], error)
}

type pesanClient struct {
	cc grpc.ClientConnInterface
}

func NewPesanClient(cc grpc.ClientConnInterface) PesanClient {
	return &pesanClient{cc}
}

func (c *pesanClient) Onboard(ctx context.Context, in *CredentialRequest, opts ...grpc.CallOption) (*ChallengeReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ChallengeReply)
	err := c.cc.Invoke(ctx, Pesan_Onboard_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pesanClient) RegisterPublicKey(ctx context.Context, in *AssertRequest, opts ...grpc.CallOption) (*AssertReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AssertReply)
	err := c.cc.Invoke(ctx, Pesan_RegisterPublicKey_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pesanClient) CreateNewProduct(ctx context.Context, in *NewProductRequest, opts ...grpc.CallOption) (*NewProductReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(NewProductReply)
	err := c.cc.Invoke(ctx, Pesan_CreateNewProduct_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pesanClient) UploadProductPhotos(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[NewPhoto, emptypb.Empty], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Pesan_ServiceDesc.Streams[0], Pesan_UploadProductPhotos_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[NewPhoto, emptypb.Empty]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Pesan_UploadProductPhotosClient = grpc.ClientStreamingClient[NewPhoto, emptypb.Empty]

// PesanServer is the server API for Pesan service.
// All implementations must embed UnimplementedPesanServer
// for forward compatibility.
type PesanServer interface {
	Onboard(context.Context, *CredentialRequest) (*ChallengeReply, error)
	RegisterPublicKey(context.Context, *AssertRequest) (*AssertReply, error)
	CreateNewProduct(context.Context, *NewProductRequest) (*NewProductReply, error)
	UploadProductPhotos(grpc.ClientStreamingServer[NewPhoto, emptypb.Empty]) error
	mustEmbedUnimplementedPesanServer()
}

// UnimplementedPesanServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPesanServer struct{}

func (UnimplementedPesanServer) Onboard(context.Context, *CredentialRequest) (*ChallengeReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Onboard not implemented")
}
func (UnimplementedPesanServer) RegisterPublicKey(context.Context, *AssertRequest) (*AssertReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterPublicKey not implemented")
}
func (UnimplementedPesanServer) CreateNewProduct(context.Context, *NewProductRequest) (*NewProductReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateNewProduct not implemented")
}
func (UnimplementedPesanServer) UploadProductPhotos(grpc.ClientStreamingServer[NewPhoto, emptypb.Empty]) error {
	return status.Errorf(codes.Unimplemented, "method UploadProductPhotos not implemented")
}
func (UnimplementedPesanServer) mustEmbedUnimplementedPesanServer() {}
func (UnimplementedPesanServer) testEmbeddedByValue()               {}

// UnsafePesanServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PesanServer will
// result in compilation errors.
type UnsafePesanServer interface {
	mustEmbedUnimplementedPesanServer()
}

func RegisterPesanServer(s grpc.ServiceRegistrar, srv PesanServer) {
	// If the following call pancis, it indicates UnimplementedPesanServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Pesan_ServiceDesc, srv)
}

func _Pesan_Onboard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CredentialRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PesanServer).Onboard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Pesan_Onboard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PesanServer).Onboard(ctx, req.(*CredentialRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pesan_RegisterPublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PesanServer).RegisterPublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Pesan_RegisterPublicKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PesanServer).RegisterPublicKey(ctx, req.(*AssertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pesan_CreateNewProduct_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewProductRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PesanServer).CreateNewProduct(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Pesan_CreateNewProduct_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PesanServer).CreateNewProduct(ctx, req.(*NewProductRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pesan_UploadProductPhotos_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PesanServer).UploadProductPhotos(&grpc.GenericServerStream[NewPhoto, emptypb.Empty]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Pesan_UploadProductPhotosServer = grpc.ClientStreamingServer[NewPhoto, emptypb.Empty]

// Pesan_ServiceDesc is the grpc.ServiceDesc for Pesan service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Pesan_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pesan.Pesan",
	HandlerType: (*PesanServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Onboard",
			Handler:    _Pesan_Onboard_Handler,
		},
		{
			MethodName: "RegisterPublicKey",
			Handler:    _Pesan_RegisterPublicKey_Handler,
		},
		{
			MethodName: "CreateNewProduct",
			Handler:    _Pesan_CreateNewProduct_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "UploadProductPhotos",
			Handler:       _Pesan_UploadProductPhotos_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "pesan.proto",
}
