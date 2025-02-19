// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v4.25.3
// source: coordinator.proto

package services

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
	Coordinator_Register_FullMethodName      = "/proto.Coordinator/Register"
	Coordinator_Connect_FullMethodName       = "/proto.Coordinator/Connect"
	Coordinator_GetFleet_FullMethodName      = "/proto.Coordinator/GetFleet"
	Coordinator_GetPoolStats_FullMethodName  = "/proto.Coordinator/GetPoolStats"
	Coordinator_CreateCluster_FullMethodName = "/proto.Coordinator/CreateCluster"
)

// CoordinatorClient is the client API for Coordinator service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CoordinatorClient interface {
	// procedure allows bot to register itself in a system
	Register(ctx context.Context, in *BotRegistrationData, opts ...grpc.CallOption) (*BotRegistrationConfirmMessage, error)
	// procedure established bidirectional connection that allow bot to collect jobs from coordinator
	Connect(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[BotState, JobStream], error)
	GetFleet(ctx context.Context, in *FleetQueryFilter, opts ...grpc.CallOption) (*Fleet, error)
	GetPoolStats(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*JobPoolStats, error)
	CreateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Cluster, error)
}

type coordinatorClient struct {
	cc grpc.ClientConnInterface
}

func NewCoordinatorClient(cc grpc.ClientConnInterface) CoordinatorClient {
	return &coordinatorClient{cc}
}

func (c *coordinatorClient) Register(ctx context.Context, in *BotRegistrationData, opts ...grpc.CallOption) (*BotRegistrationConfirmMessage, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BotRegistrationConfirmMessage)
	err := c.cc.Invoke(ctx, Coordinator_Register_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorClient) Connect(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[BotState, JobStream], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Coordinator_ServiceDesc.Streams[0], Coordinator_Connect_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[BotState, JobStream]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Coordinator_ConnectClient = grpc.BidiStreamingClient[BotState, JobStream]

func (c *coordinatorClient) GetFleet(ctx context.Context, in *FleetQueryFilter, opts ...grpc.CallOption) (*Fleet, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Fleet)
	err := c.cc.Invoke(ctx, Coordinator_GetFleet_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorClient) GetPoolStats(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*JobPoolStats, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(JobPoolStats)
	err := c.cc.Invoke(ctx, Coordinator_GetPoolStats_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorClient) CreateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Cluster, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Cluster)
	err := c.cc.Invoke(ctx, Coordinator_CreateCluster_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CoordinatorServer is the server API for Coordinator service.
// All implementations must embed UnimplementedCoordinatorServer
// for forward compatibility.
type CoordinatorServer interface {
	// procedure allows bot to register itself in a system
	Register(context.Context, *BotRegistrationData) (*BotRegistrationConfirmMessage, error)
	// procedure established bidirectional connection that allow bot to collect jobs from coordinator
	Connect(grpc.BidiStreamingServer[BotState, JobStream]) error
	GetFleet(context.Context, *FleetQueryFilter) (*Fleet, error)
	GetPoolStats(context.Context, *emptypb.Empty) (*JobPoolStats, error)
	CreateCluster(context.Context, *Cluster) (*Cluster, error)
	mustEmbedUnimplementedCoordinatorServer()
}

// UnimplementedCoordinatorServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedCoordinatorServer struct{}

func (UnimplementedCoordinatorServer) Register(context.Context, *BotRegistrationData) (*BotRegistrationConfirmMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedCoordinatorServer) Connect(grpc.BidiStreamingServer[BotState, JobStream]) error {
	return status.Errorf(codes.Unimplemented, "method Connect not implemented")
}
func (UnimplementedCoordinatorServer) GetFleet(context.Context, *FleetQueryFilter) (*Fleet, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetFleet not implemented")
}
func (UnimplementedCoordinatorServer) GetPoolStats(context.Context, *emptypb.Empty) (*JobPoolStats, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPoolStats not implemented")
}
func (UnimplementedCoordinatorServer) CreateCluster(context.Context, *Cluster) (*Cluster, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCluster not implemented")
}
func (UnimplementedCoordinatorServer) mustEmbedUnimplementedCoordinatorServer() {}
func (UnimplementedCoordinatorServer) testEmbeddedByValue()                     {}

// UnsafeCoordinatorServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CoordinatorServer will
// result in compilation errors.
type UnsafeCoordinatorServer interface {
	mustEmbedUnimplementedCoordinatorServer()
}

func RegisterCoordinatorServer(s grpc.ServiceRegistrar, srv CoordinatorServer) {
	// If the following call pancis, it indicates UnimplementedCoordinatorServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Coordinator_ServiceDesc, srv)
}

func _Coordinator_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BotRegistrationData)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Coordinator_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorServer).Register(ctx, req.(*BotRegistrationData))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coordinator_Connect_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CoordinatorServer).Connect(&grpc.GenericServerStream[BotState, JobStream]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Coordinator_ConnectServer = grpc.BidiStreamingServer[BotState, JobStream]

func _Coordinator_GetFleet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FleetQueryFilter)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorServer).GetFleet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Coordinator_GetFleet_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorServer).GetFleet(ctx, req.(*FleetQueryFilter))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coordinator_GetPoolStats_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorServer).GetPoolStats(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Coordinator_GetPoolStats_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorServer).GetPoolStats(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coordinator_CreateCluster_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorServer).CreateCluster(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Coordinator_CreateCluster_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorServer).CreateCluster(ctx, req.(*Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

// Coordinator_ServiceDesc is the grpc.ServiceDesc for Coordinator service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Coordinator_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Coordinator",
	HandlerType: (*CoordinatorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _Coordinator_Register_Handler,
		},
		{
			MethodName: "GetFleet",
			Handler:    _Coordinator_GetFleet_Handler,
		},
		{
			MethodName: "GetPoolStats",
			Handler:    _Coordinator_GetPoolStats_Handler,
		},
		{
			MethodName: "CreateCluster",
			Handler:    _Coordinator_CreateCluster_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Connect",
			Handler:       _Coordinator_Connect_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "coordinator.proto",
}
