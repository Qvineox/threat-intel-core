// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.25.3
// source: ping.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ResponseType int32

const (
	ResponseType_RT_HOST_UNKNOWN     ResponseType = 0
	ResponseType_RT_HOST_UNREACHABLE ResponseType = 1
	ResponseType_RT_FAILED           ResponseType = 2
	ResponseType_RT_TIMEOUT          ResponseType = 3
	ResponseType_RT_SUCCEEDED        ResponseType = 4
)

// Enum value maps for ResponseType.
var (
	ResponseType_name = map[int32]string{
		0: "RT_HOST_UNKNOWN",
		1: "RT_HOST_UNREACHABLE",
		2: "RT_FAILED",
		3: "RT_TIMEOUT",
		4: "RT_SUCCEEDED",
	}
	ResponseType_value = map[string]int32{
		"RT_HOST_UNKNOWN":     0,
		"RT_HOST_UNREACHABLE": 1,
		"RT_FAILED":           2,
		"RT_TIMEOUT":          3,
		"RT_SUCCEEDED":        4,
	}
)

func (x ResponseType) Enum() *ResponseType {
	p := new(ResponseType)
	*p = x
	return p
}

func (x ResponseType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ResponseType) Descriptor() protoreflect.EnumDescriptor {
	return file_ping_proto_enumTypes[0].Descriptor()
}

func (ResponseType) Type() protoreflect.EnumType {
	return &file_ping_proto_enumTypes[0]
}

func (x ResponseType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ResponseType.Descriptor instead.
func (ResponseType) EnumDescriptor() ([]byte, []int) {
	return file_ping_proto_rawDescGZIP(), []int{0}
}

type PingResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IP           string       `protobuf:"bytes,1,opt,name=IP,proto3" json:"IP,omitempty"`
	ResolvedName *string      `protobuf:"bytes,2,opt,name=ResolvedName,proto3,oneof" json:"ResolvedName,omitempty"`
	Response     ResponseType `protobuf:"varint,3,opt,name=Response,proto3,enum=proto.ResponseType" json:"Response,omitempty"`
	PacketsSent  uint32       `protobuf:"varint,4,opt,name=PacketsSent,proto3" json:"PacketsSent,omitempty"`
	PacketsLoss  float32      `protobuf:"fixed32,5,opt,name=PacketsLoss,proto3" json:"PacketsLoss,omitempty"`
	MinRtt       float32      `protobuf:"fixed32,6,opt,name=MinRtt,proto3" json:"MinRtt,omitempty"`
	MaxRtt       float32      `protobuf:"fixed32,7,opt,name=MaxRtt,proto3" json:"MaxRtt,omitempty"`
	AvgRtt       float32      `protobuf:"fixed32,8,opt,name=AvgRtt,proto3" json:"AvgRtt,omitempty"`
}

func (x *PingResult) Reset() {
	*x = PingResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ping_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingResult) ProtoMessage() {}

func (x *PingResult) ProtoReflect() protoreflect.Message {
	mi := &file_ping_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingResult.ProtoReflect.Descriptor instead.
func (*PingResult) Descriptor() ([]byte, []int) {
	return file_ping_proto_rawDescGZIP(), []int{0}
}

func (x *PingResult) GetIP() string {
	if x != nil {
		return x.IP
	}
	return ""
}

func (x *PingResult) GetResolvedName() string {
	if x != nil && x.ResolvedName != nil {
		return *x.ResolvedName
	}
	return ""
}

func (x *PingResult) GetResponse() ResponseType {
	if x != nil {
		return x.Response
	}
	return ResponseType_RT_HOST_UNKNOWN
}

func (x *PingResult) GetPacketsSent() uint32 {
	if x != nil {
		return x.PacketsSent
	}
	return 0
}

func (x *PingResult) GetPacketsLoss() float32 {
	if x != nil {
		return x.PacketsLoss
	}
	return 0
}

func (x *PingResult) GetMinRtt() float32 {
	if x != nil {
		return x.MinRtt
	}
	return 0
}

func (x *PingResult) GetMaxRtt() float32 {
	if x != nil {
		return x.MaxRtt
	}
	return 0
}

func (x *PingResult) GetAvgRtt() float32 {
	if x != nil {
		return x.AvgRtt
	}
	return 0
}

var File_ping_proto protoreflect.FileDescriptor

var file_ping_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x70, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x0d, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x93, 0x02, 0x0a, 0x0a, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12,
	0x0e, 0x0a, 0x02, 0x49, 0x50, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x49, 0x50, 0x12,
	0x27, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65,
	0x64, 0x4e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12, 0x2f, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52,
	0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x73, 0x53, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x53, 0x65, 0x6e, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x50,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x4c, 0x6f, 0x73, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x02,
	0x52, 0x0b, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x4c, 0x6f, 0x73, 0x73, 0x12, 0x16, 0x0a,
	0x06, 0x4d, 0x69, 0x6e, 0x52, 0x74, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x02, 0x52, 0x06, 0x4d,
	0x69, 0x6e, 0x52, 0x74, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x4d, 0x61, 0x78, 0x52, 0x74, 0x74, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x02, 0x52, 0x06, 0x4d, 0x61, 0x78, 0x52, 0x74, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x41, 0x76, 0x67, 0x52, 0x74, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x02, 0x52, 0x06, 0x41,
	0x76, 0x67, 0x52, 0x74, 0x74, 0x42, 0x0f, 0x0a, 0x0d, 0x5f, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76,
	0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x2a, 0x6d, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x13, 0x0a, 0x0f, 0x52, 0x54, 0x5f, 0x48, 0x4f, 0x53,
	0x54, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x52,
	0x54, 0x5f, 0x48, 0x4f, 0x53, 0x54, 0x5f, 0x55, 0x4e, 0x52, 0x45, 0x41, 0x43, 0x48, 0x41, 0x42,
	0x4c, 0x45, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x52, 0x54, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45,
	0x44, 0x10, 0x02, 0x12, 0x0e, 0x0a, 0x0a, 0x52, 0x54, 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x4f, 0x55,
	0x54, 0x10, 0x03, 0x12, 0x10, 0x0a, 0x0c, 0x52, 0x54, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x45, 0x45,
	0x44, 0x45, 0x44, 0x10, 0x04, 0x32, 0x78, 0x0a, 0x07, 0x50, 0x69, 0x6e, 0x67, 0x42, 0x6f, 0x74,
	0x12, 0x37, 0x0a, 0x09, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x12, 0x12, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x34, 0x0a, 0x0a, 0x53, 0x65, 0x74,
	0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42,
	0x26, 0x5a, 0x24, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2d,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ping_proto_rawDescOnce sync.Once
	file_ping_proto_rawDescData = file_ping_proto_rawDesc
)

func file_ping_proto_rawDescGZIP() []byte {
	file_ping_proto_rawDescOnce.Do(func() {
		file_ping_proto_rawDescData = protoimpl.X.CompressGZIP(file_ping_proto_rawDescData)
	})
	return file_ping_proto_rawDescData
}

var file_ping_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ping_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ping_proto_goTypes = []interface{}{
	(ResponseType)(0),     // 0: proto.ResponseType
	(*PingResult)(nil),    // 1: proto.PingResult
	(*PingOptions)(nil),   // 2: proto.PingOptions
	(*Timings)(nil),       // 3: proto.Timings
	(*emptypb.Empty)(nil), // 4: google.protobuf.Empty
}
var file_ping_proto_depIdxs = []int32{
	0, // 0: proto.PingResult.Response:type_name -> proto.ResponseType
	2, // 1: proto.PingBot.StartScan:input_type -> proto.PingOptions
	3, // 2: proto.PingBot.SetTimings:input_type -> proto.Timings
	4, // 3: proto.PingBot.StartScan:output_type -> google.protobuf.Empty
	4, // 4: proto.PingBot.SetTimings:output_type -> google.protobuf.Empty
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ping_proto_init() }
func file_ping_proto_init() {
	if File_ping_proto != nil {
		return
	}
	file_options_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ping_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingResult); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_ping_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ping_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_ping_proto_goTypes,
		DependencyIndexes: file_ping_proto_depIdxs,
		EnumInfos:         file_ping_proto_enumTypes,
		MessageInfos:      file_ping_proto_msgTypes,
	}.Build()
	File_ping_proto = out.File
	file_ping_proto_rawDesc = nil
	file_ping_proto_goTypes = nil
	file_ping_proto_depIdxs = nil
}
