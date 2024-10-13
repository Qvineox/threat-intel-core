// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.3
// source: ping.proto

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
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PingBotClient is the client API for PingBot service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PingBotClient interface {
	StartScan(ctx context.Context, in *PingOptions, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type pingBotClient struct {
	cc grpc.ClientConnInterface
}

func NewPingBotClient(cc grpc.ClientConnInterface) PingBotClient {
	return &pingBotClient{cc}
}

func (c *pingBotClient) StartScan(ctx context.Context, in *PingOptions, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, "/proto.PingBot/StartScan", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PingBotServer is the server API for PingBot service.
// All implementations must embed UnimplementedPingBotServer
// for forward compatibility
type PingBotServer interface {
	StartScan(context.Context, *PingOptions) (*emptypb.Empty, error)
	mustEmbedUnimplementedPingBotServer()
}

// UnimplementedPingBotServer must be embedded to have forward compatible implementations.
type UnimplementedPingBotServer struct {
}

func (UnimplementedPingBotServer) StartScan(context.Context, *PingOptions) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartScan not implemented")
}
func (UnimplementedPingBotServer) mustEmbedUnimplementedPingBotServer() {}

// UnsafePingBotServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PingBotServer will
// result in compilation errors.
type UnsafePingBotServer interface {
	mustEmbedUnimplementedPingBotServer()
}

func RegisterPingBotServer(s grpc.ServiceRegistrar, srv PingBotServer) {
	s.RegisterService(&PingBot_ServiceDesc, srv)
}

func _PingBot_StartScan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PingOptions)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PingBotServer).StartScan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.PingBot/StartScan",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PingBotServer).StartScan(ctx, req.(*PingOptions))
	}
	return interceptor(ctx, in, info, handler)
}

// PingBot_ServiceDesc is the grpc.ServiceDesc for PingBot service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PingBot_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.PingBot",
	HandlerType: (*PingBotServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StartScan",
			Handler:    _PingBot_StartScan_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "ping.proto",
}
