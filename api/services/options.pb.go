// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v4.25.3
// source: options.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Priority int32

const (
	Priority_P_LOW      Priority = 0
	Priority_P_MEDIUM   Priority = 1
	Priority_P_HIGH     Priority = 2
	Priority_P_CRITICAL Priority = 3
)

// Enum value maps for Priority.
var (
	Priority_name = map[int32]string{
		0: "P_LOW",
		1: "P_MEDIUM",
		2: "P_HIGH",
		3: "P_CRITICAL",
	}
	Priority_value = map[string]int32{
		"P_LOW":      0,
		"P_MEDIUM":   1,
		"P_HIGH":     2,
		"P_CRITICAL": 3,
	}
)

func (x Priority) Enum() *Priority {
	p := new(Priority)
	*p = x
	return p
}

func (x Priority) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Priority) Descriptor() protoreflect.EnumDescriptor {
	return file_options_proto_enumTypes[0].Descriptor()
}

func (Priority) Type() protoreflect.EnumType {
	return &file_options_proto_enumTypes[0]
}

func (x Priority) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Priority.Descriptor instead.
func (Priority) EnumDescriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{0}
}

type AssignmentMode int32

const (
	AssignmentMode_BM_LEAST_TASKS AssignmentMode = 0 // assign all tasks to the bot with lowest task count
	AssignmentMode_BM_EVEN        AssignmentMode = 1 // distribute tasks evenly between all available bots
	AssignmentMode_BM_NON_BUSY    AssignmentMode = 2 // wait for the first bot to be released
)

// Enum value maps for AssignmentMode.
var (
	AssignmentMode_name = map[int32]string{
		0: "BM_LEAST_TASKS",
		1: "BM_EVEN",
		2: "BM_NON_BUSY",
	}
	AssignmentMode_value = map[string]int32{
		"BM_LEAST_TASKS": 0,
		"BM_EVEN":        1,
		"BM_NON_BUSY":    2,
	}
)

func (x AssignmentMode) Enum() *AssignmentMode {
	p := new(AssignmentMode)
	*p = x
	return p
}

func (x AssignmentMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AssignmentMode) Descriptor() protoreflect.EnumDescriptor {
	return file_options_proto_enumTypes[1].Descriptor()
}

func (AssignmentMode) Type() protoreflect.EnumType {
	return &file_options_proto_enumTypes[1]
}

func (x AssignmentMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AssignmentMode.Descriptor instead.
func (AssignmentMode) EnumDescriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{1}
}

type JobType int32

const (
	JobType_JOB_TYPE_PING JobType = 0
)

// Enum value maps for JobType.
var (
	JobType_name = map[int32]string{
		0: "JOB_TYPE_PING",
	}
	JobType_value = map[string]int32{
		"JOB_TYPE_PING": 0,
	}
)

func (x JobType) Enum() *JobType {
	p := new(JobType)
	*p = x
	return p
}

func (x JobType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (JobType) Descriptor() protoreflect.EnumDescriptor {
	return file_options_proto_enumTypes[2].Descriptor()
}

func (JobType) Type() protoreflect.EnumType {
	return &file_options_proto_enumTypes[2]
}

func (x JobType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use JobType.Descriptor instead.
func (JobType) EnumDescriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{2}
}

type PingOptions struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Default       *Options               `protobuf:"bytes,1,opt,name=Default,proto3" json:"Default,omitempty"`
	Labels        *Labels                `protobuf:"bytes,2,opt,name=Labels,proto3" json:"Labels,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PingOptions) Reset() {
	*x = PingOptions{}
	mi := &file_options_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PingOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingOptions) ProtoMessage() {}

func (x *PingOptions) ProtoReflect() protoreflect.Message {
	mi := &file_options_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingOptions.ProtoReflect.Descriptor instead.
func (*PingOptions) Descriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{0}
}

func (x *PingOptions) GetDefault() *Options {
	if x != nil {
		return x.Default
	}
	return nil
}

func (x *PingOptions) GetLabels() *Labels {
	if x != nil {
		return x.Labels
	}
	return nil
}

type Options struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Targets       []string               `protobuf:"bytes,1,rep,name=Targets,proto3" json:"Targets,omitempty"`
	AllowForking  bool                   `protobuf:"varint,2,opt,name=AllowForking,proto3" json:"AllowForking,omitempty"`
	AllowReserved bool                   `protobuf:"varint,3,opt,name=AllowReserved,proto3" json:"AllowReserved,omitempty"`
	Shuffle       bool                   `protobuf:"varint,4,opt,name=Shuffle,proto3" json:"Shuffle,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Options) Reset() {
	*x = Options{}
	mi := &file_options_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Options) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Options) ProtoMessage() {}

func (x *Options) ProtoReflect() protoreflect.Message {
	mi := &file_options_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Options.ProtoReflect.Descriptor instead.
func (*Options) Descriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{1}
}

func (x *Options) GetTargets() []string {
	if x != nil {
		return x.Targets
	}
	return nil
}

func (x *Options) GetAllowForking() bool {
	if x != nil {
		return x.AllowForking
	}
	return false
}

func (x *Options) GetAllowReserved() bool {
	if x != nil {
		return x.AllowReserved
	}
	return false
}

func (x *Options) GetShuffle() bool {
	if x != nil {
		return x.Shuffle
	}
	return false
}

type Timings struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Timeout       uint64                 `protobuf:"varint,1,opt,name=Timeout,proto3" json:"Timeout,omitempty"`
	Delay         uint64                 `protobuf:"varint,2,opt,name=Delay,proto3" json:"Delay,omitempty"`
	Retries       uint64                 `protobuf:"varint,3,opt,name=Retries,proto3" json:"Retries,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Timings) Reset() {
	*x = Timings{}
	mi := &file_options_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Timings) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Timings) ProtoMessage() {}

func (x *Timings) ProtoReflect() protoreflect.Message {
	mi := &file_options_proto_msgTypes[2]
	if x != nil {
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
	return file_options_proto_rawDescGZIP(), []int{2}
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

type Labels struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Priority       Priority               `protobuf:"varint,1,opt,name=Priority,proto3,enum=proto.Priority" json:"Priority,omitempty"`
	AssignmentMode AssignmentMode         `protobuf:"varint,2,opt,name=AssignmentMode,proto3,enum=proto.AssignmentMode" json:"AssignmentMode,omitempty"`
	JobID          *uint64                `protobuf:"varint,3,opt,name=JobID,proto3,oneof" json:"JobID,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *Labels) Reset() {
	*x = Labels{}
	mi := &file_options_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Labels) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Labels) ProtoMessage() {}

func (x *Labels) ProtoReflect() protoreflect.Message {
	mi := &file_options_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Labels.ProtoReflect.Descriptor instead.
func (*Labels) Descriptor() ([]byte, []int) {
	return file_options_proto_rawDescGZIP(), []int{3}
}

func (x *Labels) GetPriority() Priority {
	if x != nil {
		return x.Priority
	}
	return Priority_P_LOW
}

func (x *Labels) GetAssignmentMode() AssignmentMode {
	if x != nil {
		return x.AssignmentMode
	}
	return AssignmentMode_BM_LEAST_TASKS
}

func (x *Labels) GetJobID() uint64 {
	if x != nil && x.JobID != nil {
		return *x.JobID
	}
	return 0
}

var File_options_proto protoreflect.FileDescriptor

var file_options_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5e, 0x0a, 0x0b, 0x50, 0x69, 0x6e, 0x67, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x28, 0x0a, 0x07, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x07, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x12,
	0x25, 0x0a, 0x06, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x52, 0x06,
	0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x22, 0x87, 0x01, 0x0a, 0x07, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x07, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x12, 0x22, 0x0a, 0x0c,
	0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x46, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0c, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x46, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67,
	0x12, 0x24, 0x0a, 0x0d, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x52, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x52, 0x65,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x68, 0x75, 0x66, 0x66, 0x6c,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x53, 0x68, 0x75, 0x66, 0x66, 0x6c, 0x65,
	0x22, 0x53, 0x0a, 0x07, 0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x54,
	0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x54, 0x69,
	0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x44, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x44, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x52,
	0x65, 0x74, 0x72, 0x69, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x52, 0x65,
	0x74, 0x72, 0x69, 0x65, 0x73, 0x22, 0x99, 0x01, 0x0a, 0x06, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x12, 0x2b, 0x0a, 0x08, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72,
	0x69, 0x74, 0x79, 0x52, 0x08, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x3d, 0x0a,
	0x0e, 0x41, 0x73, 0x73, 0x69, 0x67, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x6f, 0x64, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x41, 0x73,
	0x73, 0x69, 0x67, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x0e, 0x41, 0x73,
	0x73, 0x69, 0x67, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x19, 0x0a, 0x05,
	0x4a, 0x6f, 0x62, 0x49, 0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x52, 0x05, 0x4a,
	0x6f, 0x62, 0x49, 0x44, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x4a, 0x6f, 0x62, 0x49,
	0x44, 0x2a, 0x3f, 0x0a, 0x08, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x09, 0x0a,
	0x05, 0x50, 0x5f, 0x4c, 0x4f, 0x57, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x50, 0x5f, 0x4d, 0x45,
	0x44, 0x49, 0x55, 0x4d, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x50, 0x5f, 0x48, 0x49, 0x47, 0x48,
	0x10, 0x02, 0x12, 0x0e, 0x0a, 0x0a, 0x50, 0x5f, 0x43, 0x52, 0x49, 0x54, 0x49, 0x43, 0x41, 0x4c,
	0x10, 0x03, 0x2a, 0x42, 0x0a, 0x0e, 0x41, 0x73, 0x73, 0x69, 0x67, 0x6e, 0x6d, 0x65, 0x6e, 0x74,
	0x4d, 0x6f, 0x64, 0x65, 0x12, 0x12, 0x0a, 0x0e, 0x42, 0x4d, 0x5f, 0x4c, 0x45, 0x41, 0x53, 0x54,
	0x5f, 0x54, 0x41, 0x53, 0x4b, 0x53, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x42, 0x4d, 0x5f, 0x45,
	0x56, 0x45, 0x4e, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x42, 0x4d, 0x5f, 0x4e, 0x4f, 0x4e, 0x5f,
	0x42, 0x55, 0x53, 0x59, 0x10, 0x02, 0x2a, 0x1c, 0x0a, 0x07, 0x4a, 0x6f, 0x62, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x11, 0x0a, 0x0d, 0x4a, 0x4f, 0x42, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x50, 0x49,
	0x4e, 0x47, 0x10, 0x00, 0x42, 0x26, 0x5a, 0x24, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69,
	0x6e, 0x74, 0x65, 0x6c, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_options_proto_rawDescOnce sync.Once
	file_options_proto_rawDescData = file_options_proto_rawDesc
)

func file_options_proto_rawDescGZIP() []byte {
	file_options_proto_rawDescOnce.Do(func() {
		file_options_proto_rawDescData = protoimpl.X.CompressGZIP(file_options_proto_rawDescData)
	})
	return file_options_proto_rawDescData
}

var file_options_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_options_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_options_proto_goTypes = []any{
	(Priority)(0),       // 0: proto.Priority
	(AssignmentMode)(0), // 1: proto.AssignmentMode
	(JobType)(0),        // 2: proto.JobType
	(*PingOptions)(nil), // 3: proto.PingOptions
	(*Options)(nil),     // 4: proto.Options
	(*Timings)(nil),     // 5: proto.Timings
	(*Labels)(nil),      // 6: proto.Labels
}
var file_options_proto_depIdxs = []int32{
	4, // 0: proto.PingOptions.Default:type_name -> proto.Options
	6, // 1: proto.PingOptions.Labels:type_name -> proto.Labels
	0, // 2: proto.Labels.Priority:type_name -> proto.Priority
	1, // 3: proto.Labels.AssignmentMode:type_name -> proto.AssignmentMode
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_options_proto_init() }
func file_options_proto_init() {
	if File_options_proto != nil {
		return
	}
	file_options_proto_msgTypes[3].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_options_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_options_proto_goTypes,
		DependencyIndexes: file_options_proto_depIdxs,
		EnumInfos:         file_options_proto_enumTypes,
		MessageInfos:      file_options_proto_msgTypes,
	}.Build()
	File_options_proto = out.File
	file_options_proto_rawDesc = nil
	file_options_proto_goTypes = nil
	file_options_proto_depIdxs = nil
}
