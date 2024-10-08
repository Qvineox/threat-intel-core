// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.25.3
// source: nodes.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

type PingScanResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
}

func (x *PingScanResult) Reset() {
	*x = PingScanResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nodes_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingScanResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingScanResult) ProtoMessage() {}

func (x *PingScanResult) ProtoReflect() protoreflect.Message {
	mi := &file_nodes_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingScanResult.ProtoReflect.Descriptor instead.
func (*PingScanResult) Descriptor() ([]byte, []int) {
	return file_nodes_proto_rawDescGZIP(), []int{0}
}

func (x *PingScanResult) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

type ScanOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Targets []string `protobuf:"bytes,1,rep,name=targets,proto3" json:"targets,omitempty"`
	Timings *Timings `protobuf:"bytes,2,opt,name=timings,proto3" json:"timings,omitempty"`
}

func (x *ScanOptions) Reset() {
	*x = ScanOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nodes_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanOptions) ProtoMessage() {}

func (x *ScanOptions) ProtoReflect() protoreflect.Message {
	mi := &file_nodes_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanOptions.ProtoReflect.Descriptor instead.
func (*ScanOptions) Descriptor() ([]byte, []int) {
	return file_nodes_proto_rawDescGZIP(), []int{1}
}

func (x *ScanOptions) GetTargets() []string {
	if x != nil {
		return x.Targets
	}
	return nil
}

func (x *ScanOptions) GetTimings() *Timings {
	if x != nil {
		return x.Timings
	}
	return nil
}

type Timings struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Timeout uint64 `protobuf:"varint,1,opt,name=timeout,proto3" json:"timeout,omitempty"`
	Delay   uint64 `protobuf:"varint,2,opt,name=delay,proto3" json:"delay,omitempty"`
	Retries uint64 `protobuf:"varint,3,opt,name=retries,proto3" json:"retries,omitempty"`
}

func (x *Timings) Reset() {
	*x = Timings{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nodes_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Timings) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Timings) ProtoMessage() {}

func (x *Timings) ProtoReflect() protoreflect.Message {
	mi := &file_nodes_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Timings.ProtoReflect.Descriptor instead.
func (*Timings) Descriptor() ([]byte, []int) {
	return file_nodes_proto_rawDescGZIP(), []int{2}
}

func (x *Timings) GetTimeout() uint64 {
	if x != nil {
		return x.Timeout
	}
	return 0
}

func (x *Timings) GetDelay() uint64 {
	if x != nil {
		return x.Delay
	}
	return 0
}

func (x *Timings) GetRetries() uint64 {
	if x != nil {
		return x.Retries
	}
	return 0
}

type None struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *None) Reset() {
	*x = None{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nodes_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *None) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*None) ProtoMessage() {}

func (x *None) ProtoReflect() protoreflect.Message {
	mi := &file_nodes_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use None.ProtoReflect.Descriptor instead.
func (*None) Descriptor() ([]byte, []int) {
	return file_nodes_proto_rawDescGZIP(), []int{3}
}

var File_nodes_proto protoreflect.FileDescriptor

var file_nodes_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x24, 0x0a, 0x0e, 0x50, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x61,
	0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x22, 0x51, 0x0a, 0x0b, 0x53,
	0x63, 0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x73, 0x12, 0x28, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x69,
	0x6d, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x22, 0x53,
	0x0a, 0x07, 0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x69, 0x6d,
	0x65, 0x6f, 0x75, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65,
	0x6f, 0x75, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x05, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74,
	0x72, 0x69, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x65, 0x74, 0x72,
	0x69, 0x65, 0x73, 0x22, 0x06, 0x0a, 0x04, 0x4e, 0x6f, 0x6e, 0x65, 0x32, 0x39, 0x0a, 0x09, 0x50,
	0x69, 0x6e, 0x67, 0x65, 0x72, 0x42, 0x6f, 0x74, 0x12, 0x2c, 0x0a, 0x09, 0x53, 0x74, 0x61, 0x72,
	0x74, 0x53, 0x63, 0x61, 0x6e, 0x12, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x63,
	0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x0b, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x4e, 0x6f, 0x6e, 0x65, 0x42, 0x26, 0x5a, 0x24, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74,
	0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_nodes_proto_rawDescOnce sync.Once
	file_nodes_proto_rawDescData = file_nodes_proto_rawDesc
)

func file_nodes_proto_rawDescGZIP() []byte {
	file_nodes_proto_rawDescOnce.Do(func() {
		file_nodes_proto_rawDescData = protoimpl.X.CompressGZIP(file_nodes_proto_rawDescData)
	})
	return file_nodes_proto_rawDescData
}

var file_nodes_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_nodes_proto_goTypes = []interface{}{
	(*PingScanResult)(nil), // 0: proto.PingScanResult
	(*ScanOptions)(nil),    // 1: proto.ScanOptions
	(*Timings)(nil),        // 2: proto.Timings
	(*None)(nil),           // 3: proto.None
}
var file_nodes_proto_depIdxs = []int32{
	2, // 0: proto.ScanOptions.timings:type_name -> proto.Timings
	1, // 1: proto.PingerBot.StartScan:input_type -> proto.ScanOptions
	3, // 2: proto.PingerBot.StartScan:output_type -> proto.None
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_nodes_proto_init() }
func file_nodes_proto_init() {
	if File_nodes_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nodes_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingScanResult); i {
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
		file_nodes_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanOptions); i {
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
		file_nodes_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Timings); i {
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
		file_nodes_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*None); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nodes_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_nodes_proto_goTypes,
		DependencyIndexes: file_nodes_proto_depIdxs,
		MessageInfos:      file_nodes_proto_msgTypes,
	}.Build()
	File_nodes_proto = out.File
	file_nodes_proto_rawDesc = nil
	file_nodes_proto_goTypes = nil
	file_nodes_proto_depIdxs = nil
}
