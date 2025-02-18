// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v4.25.3
// source: collector.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// CollectorStatus is used to monitor collectors state
type CollectorStatus struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Identity       string                 `protobuf:"bytes,1,opt,name=Identity,proto3" json:"Identity,omitempty"`
	LoadPercentage uint64                 `protobuf:"varint,2,opt,name=LoadPercentage,proto3" json:"LoadPercentage,omitempty"`
	Queue          *CollectorQueueState   `protobuf:"bytes,3,opt,name=Queue,proto3" json:"Queue,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *CollectorStatus) Reset() {
	*x = CollectorStatus{}
	mi := &file_collector_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CollectorStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CollectorStatus) ProtoMessage() {}

func (x *CollectorStatus) ProtoReflect() protoreflect.Message {
	mi := &file_collector_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CollectorStatus.ProtoReflect.Descriptor instead.
func (*CollectorStatus) Descriptor() ([]byte, []int) {
	return file_collector_proto_rawDescGZIP(), []int{0}
}

func (x *CollectorStatus) GetIdentity() string {
	if x != nil {
		return x.Identity
	}
	return ""
}

func (x *CollectorStatus) GetLoadPercentage() uint64 {
	if x != nil {
		return x.LoadPercentage
	}
	return 0
}

func (x *CollectorStatus) GetQueue() *CollectorQueueState {
	if x != nil {
		return x.Queue
	}
	return nil
}

type CollectorQueueState struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Cap           int32                  `protobuf:"varint,1,opt,name=Cap,proto3" json:"Cap,omitempty"`
	Len           int32                  `protobuf:"varint,2,opt,name=Len,proto3" json:"Len,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CollectorQueueState) Reset() {
	*x = CollectorQueueState{}
	mi := &file_collector_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CollectorQueueState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CollectorQueueState) ProtoMessage() {}

func (x *CollectorQueueState) ProtoReflect() protoreflect.Message {
	mi := &file_collector_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CollectorQueueState.ProtoReflect.Descriptor instead.
func (*CollectorQueueState) Descriptor() ([]byte, []int) {
	return file_collector_proto_rawDescGZIP(), []int{1}
}

func (x *CollectorQueueState) GetCap() int32 {
	if x != nil {
		return x.Cap
	}
	return 0
}

func (x *CollectorQueueState) GetLen() int32 {
	if x != nil {
		return x.Len
	}
	return 0
}

var File_collector_proto protoreflect.FileDescriptor

var file_collector_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0a, 0x70, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x87, 0x01, 0x0a, 0x0f, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x12, 0x26, 0x0a, 0x0e, 0x4c, 0x6f, 0x61, 0x64, 0x50, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74,
	0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x4c, 0x6f, 0x61, 0x64, 0x50,
	0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x12, 0x30, 0x0a, 0x05, 0x51, 0x75, 0x65,
	0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x51, 0x75, 0x65, 0x75, 0x65, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x51, 0x75, 0x65, 0x75, 0x65, 0x22, 0x39, 0x0a, 0x13, 0x43,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x51, 0x75, 0x65, 0x75, 0x65, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x43, 0x61, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x03, 0x43, 0x61, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x4c, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x03, 0x4c, 0x65, 0x6e, 0x32, 0x87, 0x01, 0x0a, 0x10, 0x43, 0x6f, 0x6c, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x39, 0x0a, 0x0c, 0x50,
	0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x11, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x38, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x42, 0x26, 0x5a, 0x24, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c,
	0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_collector_proto_rawDescOnce sync.Once
	file_collector_proto_rawDescData = file_collector_proto_rawDesc
)

func file_collector_proto_rawDescGZIP() []byte {
	file_collector_proto_rawDescOnce.Do(func() {
		file_collector_proto_rawDescData = protoimpl.X.CompressGZIP(file_collector_proto_rawDescData)
	})
	return file_collector_proto_rawDescData
}

var file_collector_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_collector_proto_goTypes = []any{
	(*CollectorStatus)(nil),     // 0: proto.CollectorStatus
	(*CollectorQueueState)(nil), // 1: proto.CollectorQueueState
	(*PingResult)(nil),          // 2: proto.PingResult
	(*emptypb.Empty)(nil),       // 3: google.protobuf.Empty
}
var file_collector_proto_depIdxs = []int32{
	1, // 0: proto.CollectorStatus.Queue:type_name -> proto.CollectorQueueState
	2, // 1: proto.CollectorService.PingResponse:input_type -> proto.PingResult
	3, // 2: proto.CollectorService.Status:input_type -> google.protobuf.Empty
	3, // 3: proto.CollectorService.PingResponse:output_type -> google.protobuf.Empty
	0, // 4: proto.CollectorService.Status:output_type -> proto.CollectorStatus
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_collector_proto_init() }
func file_collector_proto_init() {
	if File_collector_proto != nil {
		return
	}
	file_ping_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_collector_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_collector_proto_goTypes,
		DependencyIndexes: file_collector_proto_depIdxs,
		MessageInfos:      file_collector_proto_msgTypes,
	}.Build()
	File_collector_proto = out.File
	file_collector_proto_rawDesc = nil
	file_collector_proto_goTypes = nil
	file_collector_proto_depIdxs = nil
}
