// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v4.25.3
// source: cc.proto

package services

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/apipb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Jobs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Jobs []*Job `protobuf:"bytes,1,rep,name=Jobs,proto3" json:"Jobs,omitempty"`
}

func (x *Jobs) Reset() {
	*x = Jobs{}
	mi := &file_cc_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Jobs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Jobs) ProtoMessage() {}

func (x *Jobs) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Jobs.ProtoReflect.Descriptor instead.
func (*Jobs) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{0}
}

func (x *Jobs) GetJobs() []*Job {
	if x != nil {
		return x.Jobs
	}
	return nil
}

type Job struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ID *uint64 `protobuf:"varint,1,opt,name=ID,proto3,oneof" json:"ID,omitempty"`
	// Type described in entities package
	// can be one of the following: P (ping)
	Type string `protobuf:"bytes,2,opt,name=Type,proto3" json:"Type,omitempty"`
	// State described in entities package
	// can be one of the following: queued, started, completed, error
	State string `protobuf:"bytes,3,opt,name=State,proto3" json:"State,omitempty"`
	// Full job parameters and targets as requested in job, stored as JSON binary
	Options   [][]byte               `protobuf:"bytes,4,rep,name=Options,proto3" json:"Options,omitempty"`
	ErrorText *string                `protobuf:"bytes,5,opt,name=ErrorText,proto3,oneof" json:"ErrorText,omitempty"`
	CreatedBy *uint64                `protobuf:"varint,6,opt,name=CreatedBy,proto3,oneof" json:"CreatedBy,omitempty"`
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty"`
	UpdatedAt *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty"`
}

func (x *Job) Reset() {
	*x = Job{}
	mi := &file_cc_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Job) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Job) ProtoMessage() {}

func (x *Job) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Job.ProtoReflect.Descriptor instead.
func (*Job) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{1}
}

func (x *Job) GetID() uint64 {
	if x != nil && x.ID != nil {
		return *x.ID
	}
	return 0
}

func (x *Job) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Job) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *Job) GetOptions() [][]byte {
	if x != nil {
		return x.Options
	}
	return nil
}

func (x *Job) GetErrorText() string {
	if x != nil && x.ErrorText != nil {
		return *x.ErrorText
	}
	return ""
}

func (x *Job) GetCreatedBy() uint64 {
	if x != nil && x.CreatedBy != nil {
		return *x.CreatedBy
	}
	return 0
}

func (x *Job) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Job) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

var File_cc_proto protoreflect.FileDescriptor

var file_cc_proto_rawDesc = []byte{
	0x0a, 0x08, 0x63, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70,
	0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0d, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0b, 0x66, 0x6c, 0x65, 0x65, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x26, 0x0a, 0x04, 0x4a, 0x6f, 0x62, 0x73, 0x12, 0x1e, 0x0a, 0x04,
	0x4a, 0x6f, 0x62, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x52, 0x04, 0x4a, 0x6f, 0x62, 0x73, 0x22, 0xbb, 0x02, 0x0a,
	0x03, 0x4a, 0x6f, 0x62, 0x12, 0x13, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04,
	0x48, 0x00, 0x52, 0x02, 0x49, 0x44, 0x88, 0x01, 0x01, 0x12, 0x12, 0x0a, 0x04, 0x54, 0x79, 0x70,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a,
	0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x21, 0x0a,
	0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x01, 0x52, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x88, 0x01, 0x01,
	0x12, 0x21, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x04, 0x48, 0x02, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79,
	0x88, 0x01, 0x01, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a,
	0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x42, 0x05, 0x0a, 0x03, 0x5f, 0x49, 0x44, 0x42, 0x0c,
	0x0a, 0x0a, 0x5f, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x42, 0x0c, 0x0a, 0x0a,
	0x5f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x32, 0xee, 0x01, 0x0a, 0x0d, 0x43,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x44, 0x0a, 0x08,
	0x47, 0x65, 0x74, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x12, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x1a, 0x0c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x22,
	0x11, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0b, 0x12, 0x09, 0x2f, 0x76, 0x31, 0x2f, 0x66, 0x6c, 0x65,
	0x65, 0x74, 0x12, 0x55, 0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x69, 0x6e, 0x67,
	0x4a, 0x6f, 0x62, 0x12, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67,
	0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22,
	0x18, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x12, 0x3a, 0x01, 0x2a, 0x22, 0x0d, 0x2f, 0x76, 0x31, 0x2f,
	0x6a, 0x6f, 0x62, 0x73, 0x2f, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x40, 0x0a, 0x07, 0x47, 0x65, 0x74,
	0x4a, 0x6f, 0x62, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0b, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x73, 0x22, 0x10, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x0a, 0x12, 0x08, 0x2f, 0x76, 0x31, 0x2f, 0x6a, 0x6f, 0x62, 0x73, 0x42, 0x26, 0x5a, 0x24, 0x74,
	0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2d, 0x63, 0x6f, 0x72, 0x65,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cc_proto_rawDescOnce sync.Once
	file_cc_proto_rawDescData = file_cc_proto_rawDesc
)

func file_cc_proto_rawDescGZIP() []byte {
	file_cc_proto_rawDescOnce.Do(func() {
		file_cc_proto_rawDescData = protoimpl.X.CompressGZIP(file_cc_proto_rawDescData)
	})
	return file_cc_proto_rawDescData
}

var file_cc_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cc_proto_goTypes = []any{
	(*Jobs)(nil),                  // 0: proto.Jobs
	(*Job)(nil),                   // 1: proto.Job
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
	(*FleetQueryFilter)(nil),      // 3: proto.FleetQueryFilter
	(*PingOptions)(nil),           // 4: proto.PingOptions
	(*emptypb.Empty)(nil),         // 5: google.protobuf.Empty
	(*Fleet)(nil),                 // 6: proto.Fleet
}
var file_cc_proto_depIdxs = []int32{
	1, // 0: proto.Jobs.Jobs:type_name -> proto.Job
	2, // 1: proto.Job.CreatedAt:type_name -> google.protobuf.Timestamp
	2, // 2: proto.Job.UpdatedAt:type_name -> google.protobuf.Timestamp
	3, // 3: proto.ControlCenter.GetFleet:input_type -> proto.FleetQueryFilter
	4, // 4: proto.ControlCenter.CreatePingJob:input_type -> proto.PingOptions
	5, // 5: proto.ControlCenter.GetJobs:input_type -> google.protobuf.Empty
	6, // 6: proto.ControlCenter.GetFleet:output_type -> proto.Fleet
	5, // 7: proto.ControlCenter.CreatePingJob:output_type -> google.protobuf.Empty
	0, // 8: proto.ControlCenter.GetJobs:output_type -> proto.Jobs
	6, // [6:9] is the sub-list for method output_type
	3, // [3:6] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_cc_proto_init() }
func file_cc_proto_init() {
	if File_cc_proto != nil {
		return
	}
	file_options_proto_init()
	file_fleet_proto_init()
	file_cc_proto_msgTypes[1].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cc_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cc_proto_goTypes,
		DependencyIndexes: file_cc_proto_depIdxs,
		MessageInfos:      file_cc_proto_msgTypes,
	}.Build()
	File_cc_proto = out.File
	file_cc_proto_rawDesc = nil
	file_cc_proto_goTypes = nil
	file_cc_proto_depIdxs = nil
}
