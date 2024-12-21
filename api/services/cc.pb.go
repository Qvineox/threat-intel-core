// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
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
	return file_cc_proto_enumTypes[0].Descriptor()
}

func (JobType) Type() protoreflect.EnumType {
	return &file_cc_proto_enumTypes[0]
}

func (x JobType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use JobType.Descriptor instead.
func (JobType) EnumDescriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{0}
}

type Jobs struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Jobs          []*Job                 `protobuf:"bytes,1,rep,name=Jobs,proto3" json:"Jobs,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
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
	state protoimpl.MessageState `protogen:"open.v1"`
	ID    *uint64                `protobuf:"varint,1,opt,name=ID,proto3,oneof" json:"ID,omitempty"`
	// Type described in entities package
	Type JobType `protobuf:"varint,2,opt,name=Type,proto3,enum=proto.JobType" json:"Type,omitempty"`
	// IsSent defines if job has been sent to processing
	IsSent bool `protobuf:"varint,3,opt,name=IsSent,proto3" json:"IsSent,omitempty"`
	// Full job parameters and targets as requested in job, stored as JSON binary
	Options       []byte                 `protobuf:"bytes,4,opt,name=Options,proto3" json:"Options,omitempty"`
	ErrorText     *string                `protobuf:"bytes,5,opt,name=ErrorText,proto3,oneof" json:"ErrorText,omitempty"`
	CreatedBy     *uint64                `protobuf:"varint,6,opt,name=CreatedBy,proto3,oneof" json:"CreatedBy,omitempty"`
	CreatedAt     *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty"`
	UpdatedAt     *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
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

func (x *Job) GetType() JobType {
	if x != nil {
		return x.Type
	}
	return JobType_JOB_TYPE_PING
}

func (x *Job) GetIsSent() bool {
	if x != nil {
		return x.IsSent
	}
	return false
}

func (x *Job) GetOptions() []byte {
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

type JobsQueryFilter struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            uint64                 `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Types         []JobType              `protobuf:"varint,2,rep,packed,name=Types,proto3,enum=proto.JobType" json:"Types,omitempty"`
	CreatedBy     uint64                 `protobuf:"varint,3,opt,name=CreatedBy,proto3" json:"CreatedBy,omitempty"`
	ErrorText     string                 `protobuf:"bytes,4,opt,name=ErrorText,proto3" json:"ErrorText,omitempty"`
	CreatedAfter  *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=CreatedAfter,proto3" json:"CreatedAfter,omitempty"`
	CreatedBefore *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=CreatedBefore,proto3" json:"CreatedBefore,omitempty"`
	Limit         uint64                 `protobuf:"varint,7,opt,name=Limit,proto3" json:"Limit,omitempty"`
	Offset        uint64                 `protobuf:"varint,8,opt,name=Offset,proto3" json:"Offset,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *JobsQueryFilter) Reset() {
	*x = JobsQueryFilter{}
	mi := &file_cc_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JobsQueryFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JobsQueryFilter) ProtoMessage() {}

func (x *JobsQueryFilter) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JobsQueryFilter.ProtoReflect.Descriptor instead.
func (*JobsQueryFilter) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{2}
}

func (x *JobsQueryFilter) GetID() uint64 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *JobsQueryFilter) GetTypes() []JobType {
	if x != nil {
		return x.Types
	}
	return nil
}

func (x *JobsQueryFilter) GetCreatedBy() uint64 {
	if x != nil {
		return x.CreatedBy
	}
	return 0
}

func (x *JobsQueryFilter) GetErrorText() string {
	if x != nil {
		return x.ErrorText
	}
	return ""
}

func (x *JobsQueryFilter) GetCreatedAfter() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAfter
	}
	return nil
}

func (x *JobsQueryFilter) GetCreatedBefore() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedBefore
	}
	return nil
}

func (x *JobsQueryFilter) GetLimit() uint64 {
	if x != nil {
		return x.Limit
	}
	return 0
}

func (x *JobsQueryFilter) GetOffset() uint64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

type TargetsEvaluationMessage struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Body          string                 `protobuf:"bytes,1,opt,name=Body,proto3" json:"Body,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TargetsEvaluationMessage) Reset() {
	*x = TargetsEvaluationMessage{}
	mi := &file_cc_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TargetsEvaluationMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetsEvaluationMessage) ProtoMessage() {}

func (x *TargetsEvaluationMessage) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetsEvaluationMessage.ProtoReflect.Descriptor instead.
func (*TargetsEvaluationMessage) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{3}
}

func (x *TargetsEvaluationMessage) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

type TargetsEvaluationResult struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Domains       uint64                 `protobuf:"varint,1,opt,name=Domains,proto3" json:"Domains,omitempty"`
	URLs          uint64                 `protobuf:"varint,2,opt,name=URLs,proto3" json:"URLs,omitempty"`
	Subnets       uint64                 `protobuf:"varint,3,opt,name=Subnets,proto3" json:"Subnets,omitempty"`
	IPs           uint64                 `protobuf:"varint,4,opt,name=IPs,proto3" json:"IPs,omitempty"`
	Emails        uint64                 `protobuf:"varint,5,opt,name=Emails,proto3" json:"Emails,omitempty"`
	Total         uint64                 `protobuf:"varint,6,opt,name=Total,proto3" json:"Total,omitempty"`
	Errors        []string               `protobuf:"bytes,7,rep,name=Errors,proto3" json:"Errors,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TargetsEvaluationResult) Reset() {
	*x = TargetsEvaluationResult{}
	mi := &file_cc_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TargetsEvaluationResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetsEvaluationResult) ProtoMessage() {}

func (x *TargetsEvaluationResult) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetsEvaluationResult.ProtoReflect.Descriptor instead.
func (*TargetsEvaluationResult) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{4}
}

func (x *TargetsEvaluationResult) GetDomains() uint64 {
	if x != nil {
		return x.Domains
	}
	return 0
}

func (x *TargetsEvaluationResult) GetURLs() uint64 {
	if x != nil {
		return x.URLs
	}
	return 0
}

func (x *TargetsEvaluationResult) GetSubnets() uint64 {
	if x != nil {
		return x.Subnets
	}
	return 0
}

func (x *TargetsEvaluationResult) GetIPs() uint64 {
	if x != nil {
		return x.IPs
	}
	return 0
}

func (x *TargetsEvaluationResult) GetEmails() uint64 {
	if x != nil {
		return x.Emails
	}
	return 0
}

func (x *TargetsEvaluationResult) GetTotal() uint64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *TargetsEvaluationResult) GetErrors() []string {
	if x != nil {
		return x.Errors
	}
	return nil
}

type UUID struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Value         string                 `protobuf:"bytes,1,opt,name=Value,proto3" json:"Value,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UUID) Reset() {
	*x = UUID{}
	mi := &file_cc_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UUID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UUID) ProtoMessage() {}

func (x *UUID) ProtoReflect() protoreflect.Message {
	mi := &file_cc_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UUID.ProtoReflect.Descriptor instead.
func (*UUID) Descriptor() ([]byte, []int) {
	return file_cc_proto_rawDescGZIP(), []int{5}
}

func (x *UUID) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
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
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0a, 0x70, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x26, 0x0a, 0x04, 0x4a, 0x6f, 0x62, 0x73, 0x12, 0x1e, 0x0a, 0x04, 0x4a, 0x6f, 0x62, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a,
	0x6f, 0x62, 0x52, 0x04, 0x4a, 0x6f, 0x62, 0x73, 0x22, 0xcd, 0x02, 0x0a, 0x03, 0x4a, 0x6f, 0x62,
	0x12, 0x13, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x52, 0x02,
	0x49, 0x44, 0x88, 0x01, 0x01, 0x12, 0x22, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x73, 0x53,
	0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x49, 0x73, 0x53, 0x65, 0x6e,
	0x74, 0x12, 0x18, 0x0a, 0x07, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x21, 0x0a, 0x09, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01,
	0x52, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x88, 0x01, 0x01, 0x12, 0x21,
	0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x04, 0x48, 0x02, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x88, 0x01,
	0x01, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x64, 0x41, 0x74, 0x42, 0x05, 0x0a, 0x03, 0x5f, 0x49, 0x44, 0x42, 0x0c, 0x0a, 0x0a,
	0x5f, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x22, 0xb3, 0x02, 0x0a, 0x0f, 0x4a, 0x6f, 0x62,
	0x73, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02,
	0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x49, 0x44, 0x12, 0x24, 0x0a, 0x05,
	0x54, 0x79, 0x70, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x54, 0x79, 0x70, 0x65, 0x52, 0x05, 0x54, 0x79, 0x70,
	0x65, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79,
	0x12, 0x1c, 0x0a, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x54, 0x65, 0x78, 0x74, 0x12, 0x3e,
	0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x66, 0x74, 0x65, 0x72, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x66, 0x74, 0x65, 0x72, 0x12, 0x40,
	0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x05, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x22, 0x2e,
	0x0a, 0x18, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x42, 0x6f,
	0x64, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x42, 0x6f, 0x64, 0x79, 0x22, 0xb9,
	0x01, 0x0a, 0x17, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x44, 0x6f,
	0x6d, 0x61, 0x69, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x44, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x55, 0x52, 0x4c, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x04, 0x55, 0x52, 0x4c, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x75, 0x62, 0x6e,
	0x65, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x53, 0x75, 0x62, 0x6e, 0x65,
	0x74, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x49, 0x50, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x03, 0x49, 0x50, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x14, 0x0a, 0x05,
	0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x54, 0x6f, 0x74,
	0x61, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x06, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x22, 0x1c, 0x0a, 0x04, 0x55, 0x55,
	0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x2a, 0x1c, 0x0a, 0x07, 0x4a, 0x6f, 0x62, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x11, 0x0a, 0x0d, 0x4a, 0x4f, 0x42, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x50, 0x49, 0x4e, 0x47, 0x10, 0x00, 0x32, 0x81, 0x04, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x43, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x44, 0x0a, 0x08, 0x47, 0x65, 0x74, 0x46,
	0x6c, 0x65, 0x65, 0x74, 0x12, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x46, 0x6c, 0x65,
	0x65, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x1a, 0x0c, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x22, 0x11, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x0b, 0x12, 0x09, 0x2f, 0x76, 0x31, 0x2f, 0x66, 0x6c, 0x65, 0x65, 0x74, 0x12, 0x55,
	0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x69, 0x6e, 0x67, 0x4a, 0x6f, 0x62, 0x12,
	0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x4f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x18, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x12, 0x3a, 0x01, 0x2a, 0x22, 0x0d, 0x2f, 0x76, 0x31, 0x2f, 0x6a, 0x6f, 0x62, 0x73,
	0x2f, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x6d, 0x0a, 0x0c, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74,
	0x65, 0x4a, 0x6f, 0x62, 0x73, 0x12, 0x1f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x73, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x1e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x1c, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x16, 0x3a, 0x01,
	0x2a, 0x22, 0x11, 0x2f, 0x76, 0x31, 0x2f, 0x6a, 0x6f, 0x62, 0x73, 0x2f, 0x65, 0x76, 0x61, 0x6c,
	0x75, 0x61, 0x74, 0x65, 0x12, 0x40, 0x0a, 0x07, 0x47, 0x65, 0x74, 0x4a, 0x6f, 0x62, 0x73, 0x12,
	0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x73, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x1a, 0x0b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x4a, 0x6f, 0x62, 0x73, 0x22, 0x10, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0a, 0x12, 0x08, 0x2f, 0x76,
	0x31, 0x2f, 0x6a, 0x6f, 0x62, 0x73, 0x12, 0x43, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x4e, 0x65, 0x77,
	0x55, 0x55, 0x49, 0x44, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0b, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x22, 0x10, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x0a, 0x12, 0x08, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x75, 0x69, 0x64, 0x12, 0x5d, 0x0a, 0x0e, 0x47,
	0x65, 0x74, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x12, 0x1d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x73, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x1a, 0x12, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73,
	0x22, 0x18, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x12, 0x12, 0x10, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x73, 0x2f, 0x70, 0x69, 0x6e, 0x67, 0x42, 0x26, 0x5a, 0x24, 0x74, 0x68,
	0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_cc_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_cc_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_cc_proto_goTypes = []any{
	(JobType)(0),                     // 0: proto.JobType
	(*Jobs)(nil),                     // 1: proto.Jobs
	(*Job)(nil),                      // 2: proto.Job
	(*JobsQueryFilter)(nil),          // 3: proto.JobsQueryFilter
	(*TargetsEvaluationMessage)(nil), // 4: proto.TargetsEvaluationMessage
	(*TargetsEvaluationResult)(nil),  // 5: proto.TargetsEvaluationResult
	(*UUID)(nil),                     // 6: proto.UUID
	(*timestamppb.Timestamp)(nil),    // 7: google.protobuf.Timestamp
	(*FleetQueryFilter)(nil),         // 8: proto.FleetQueryFilter
	(*PingOptions)(nil),              // 9: proto.PingOptions
	(*emptypb.Empty)(nil),            // 10: google.protobuf.Empty
	(*PingResultsQueryFilter)(nil),   // 11: proto.PingResultsQueryFilter
	(*Fleet)(nil),                    // 12: proto.Fleet
	(*PingResults)(nil),              // 13: proto.PingResults
}
var file_cc_proto_depIdxs = []int32{
	2,  // 0: proto.Jobs.Jobs:type_name -> proto.Job
	0,  // 1: proto.Job.Type:type_name -> proto.JobType
	7,  // 2: proto.Job.CreatedAt:type_name -> google.protobuf.Timestamp
	7,  // 3: proto.Job.UpdatedAt:type_name -> google.protobuf.Timestamp
	0,  // 4: proto.JobsQueryFilter.Types:type_name -> proto.JobType
	7,  // 5: proto.JobsQueryFilter.CreatedAfter:type_name -> google.protobuf.Timestamp
	7,  // 6: proto.JobsQueryFilter.CreatedBefore:type_name -> google.protobuf.Timestamp
	8,  // 7: proto.ControlCenter.GetFleet:input_type -> proto.FleetQueryFilter
	9,  // 8: proto.ControlCenter.CreatePingJob:input_type -> proto.PingOptions
	4,  // 9: proto.ControlCenter.EvaluateJobs:input_type -> proto.TargetsEvaluationMessage
	3,  // 10: proto.ControlCenter.GetJobs:input_type -> proto.JobsQueryFilter
	10, // 11: proto.ControlCenter.GetNewUUID:input_type -> google.protobuf.Empty
	11, // 12: proto.ControlCenter.GetPingResults:input_type -> proto.PingResultsQueryFilter
	12, // 13: proto.ControlCenter.GetFleet:output_type -> proto.Fleet
	10, // 14: proto.ControlCenter.CreatePingJob:output_type -> google.protobuf.Empty
	5,  // 15: proto.ControlCenter.EvaluateJobs:output_type -> proto.TargetsEvaluationResult
	1,  // 16: proto.ControlCenter.GetJobs:output_type -> proto.Jobs
	6,  // 17: proto.ControlCenter.GetNewUUID:output_type -> proto.UUID
	13, // 18: proto.ControlCenter.GetPingResults:output_type -> proto.PingResults
	13, // [13:19] is the sub-list for method output_type
	7,  // [7:13] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_cc_proto_init() }
func file_cc_proto_init() {
	if File_cc_proto != nil {
		return
	}
	file_options_proto_init()
	file_fleet_proto_init()
	file_ping_proto_init()
	file_cc_proto_msgTypes[1].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cc_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cc_proto_goTypes,
		DependencyIndexes: file_cc_proto_depIdxs,
		EnumInfos:         file_cc_proto_enumTypes,
		MessageInfos:      file_cc_proto_msgTypes,
	}.Build()
	File_cc_proto = out.File
	file_cc_proto_rawDesc = nil
	file_cc_proto_goTypes = nil
	file_cc_proto_depIdxs = nil
}
