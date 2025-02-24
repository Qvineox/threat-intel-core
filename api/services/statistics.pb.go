// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v4.25.3
// source: statistics.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/emptypb"
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

type ScanStatisticsQueryFilter struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	JobType       JobType                `protobuf:"varint,1,opt,name=JobType,proto3,enum=proto.JobType" json:"JobType,omitempty"`
	After         *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=After,proto3" json:"After,omitempty"`
	Before        *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=Before,proto3" json:"Before,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ScanStatisticsQueryFilter) Reset() {
	*x = ScanStatisticsQueryFilter{}
	mi := &file_statistics_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ScanStatisticsQueryFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanStatisticsQueryFilter) ProtoMessage() {}

func (x *ScanStatisticsQueryFilter) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanStatisticsQueryFilter.ProtoReflect.Descriptor instead.
func (*ScanStatisticsQueryFilter) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{0}
}

func (x *ScanStatisticsQueryFilter) GetJobType() JobType {
	if x != nil {
		return x.JobType
	}
	return JobType_JOB_TYPE_PING
}

func (x *ScanStatisticsQueryFilter) GetAfter() *timestamppb.Timestamp {
	if x != nil {
		return x.After
	}
	return nil
}

func (x *ScanStatisticsQueryFilter) GetBefore() *timestamppb.Timestamp {
	if x != nil {
		return x.Before
	}
	return nil
}

type ScanStatistics struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Data:
	//
	//	*ScanStatistics_Ping
	Data          isScanStatistics_Data `protobuf_oneof:"Data"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ScanStatistics) Reset() {
	*x = ScanStatistics{}
	mi := &file_statistics_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ScanStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanStatistics) ProtoMessage() {}

func (x *ScanStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanStatistics.ProtoReflect.Descriptor instead.
func (*ScanStatistics) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{1}
}

func (x *ScanStatistics) GetData() isScanStatistics_Data {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *ScanStatistics) GetPing() *PingScanStatistics {
	if x != nil {
		if x, ok := x.Data.(*ScanStatistics_Ping); ok {
			return x.Ping
		}
	}
	return nil
}

type isScanStatistics_Data interface {
	isScanStatistics_Data()
}

type ScanStatistics_Ping struct {
	Ping *PingScanStatistics `protobuf:"bytes,1,opt,name=Ping,proto3,oneof"`
}

func (*ScanStatistics_Ping) isScanStatistics_Data() {}

type CommonStatistics struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	TotalScans      uint64                 `protobuf:"varint,1,opt,name=TotalScans,proto3" json:"TotalScans,omitempty"`
	SuccessfulScans uint64                 `protobuf:"varint,2,opt,name=SuccessfulScans,proto3" json:"SuccessfulScans,omitempty"`
	FailedScans     uint64                 `protobuf:"varint,3,opt,name=FailedScans,proto3" json:"FailedScans,omitempty"`
	DistinctIPs     uint64                 `protobuf:"varint,4,opt,name=DistinctIPs,proto3" json:"DistinctIPs,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *CommonStatistics) Reset() {
	*x = CommonStatistics{}
	mi := &file_statistics_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CommonStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommonStatistics) ProtoMessage() {}

func (x *CommonStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommonStatistics.ProtoReflect.Descriptor instead.
func (*CommonStatistics) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{2}
}

func (x *CommonStatistics) GetTotalScans() uint64 {
	if x != nil {
		return x.TotalScans
	}
	return 0
}

func (x *CommonStatistics) GetSuccessfulScans() uint64 {
	if x != nil {
		return x.SuccessfulScans
	}
	return 0
}

func (x *CommonStatistics) GetFailedScans() uint64 {
	if x != nil {
		return x.FailedScans
	}
	return 0
}

func (x *CommonStatistics) GetDistinctIPs() uint64 {
	if x != nil {
		return x.DistinctIPs
	}
	return 0
}

type PingScanStatistics struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Common        *CommonStatistics      `protobuf:"bytes,1,opt,name=Common,proto3" json:"Common,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PingScanStatistics) Reset() {
	*x = PingScanStatistics{}
	mi := &file_statistics_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PingScanStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingScanStatistics) ProtoMessage() {}

func (x *PingScanStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingScanStatistics.ProtoReflect.Descriptor instead.
func (*PingScanStatistics) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{3}
}

func (x *PingScanStatistics) GetCommon() *CommonStatistics {
	if x != nil {
		return x.Common
	}
	return nil
}

type CoverageStatisticsQueryFilter struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	JobType       JobType                `protobuf:"varint,1,opt,name=JobType,proto3,enum=proto.JobType" json:"JobType,omitempty"`
	After         *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=After,proto3" json:"After,omitempty"`
	Before        *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=Before,proto3" json:"Before,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CoverageStatisticsQueryFilter) Reset() {
	*x = CoverageStatisticsQueryFilter{}
	mi := &file_statistics_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CoverageStatisticsQueryFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CoverageStatisticsQueryFilter) ProtoMessage() {}

func (x *CoverageStatisticsQueryFilter) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CoverageStatisticsQueryFilter.ProtoReflect.Descriptor instead.
func (*CoverageStatisticsQueryFilter) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{4}
}

func (x *CoverageStatisticsQueryFilter) GetJobType() JobType {
	if x != nil {
		return x.JobType
	}
	return JobType_JOB_TYPE_PING
}

func (x *CoverageStatisticsQueryFilter) GetAfter() *timestamppb.Timestamp {
	if x != nil {
		return x.After
	}
	return nil
}

func (x *CoverageStatisticsQueryFilter) GetBefore() *timestamppb.Timestamp {
	if x != nil {
		return x.Before
	}
	return nil
}

type CoverageStatistics struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	TotalScans        uint64                 `protobuf:"varint,1,opt,name=TotalScans,proto3" json:"TotalScans,omitempty"` // scanned in a time frame
	DistinctIPs       uint64                 `protobuf:"varint,2,opt,name=DistinctIPs,proto3" json:"DistinctIPs,omitempty"`
	PercentOfSavedIPs uint64                 `protobuf:"varint,3,opt,name=PercentOfSavedIPs,proto3" json:"PercentOfSavedIPs,omitempty"` // percentage of scanned IP addresses to total amount of distinct IPs already saved in a system
	PercentOfTotalIPs uint64                 `protobuf:"varint,4,opt,name=PercentOfTotalIPs,proto3" json:"PercentOfTotalIPs,omitempty"` // percentage of scanned IP addresses to total amount of available IPs
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *CoverageStatistics) Reset() {
	*x = CoverageStatistics{}
	mi := &file_statistics_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CoverageStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CoverageStatistics) ProtoMessage() {}

func (x *CoverageStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_statistics_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CoverageStatistics.ProtoReflect.Descriptor instead.
func (*CoverageStatistics) Descriptor() ([]byte, []int) {
	return file_statistics_proto_rawDescGZIP(), []int{5}
}

func (x *CoverageStatistics) GetTotalScans() uint64 {
	if x != nil {
		return x.TotalScans
	}
	return 0
}

func (x *CoverageStatistics) GetDistinctIPs() uint64 {
	if x != nil {
		return x.DistinctIPs
	}
	return 0
}

func (x *CoverageStatistics) GetPercentOfSavedIPs() uint64 {
	if x != nil {
		return x.PercentOfSavedIPs
	}
	return 0
}

func (x *CoverageStatistics) GetPercentOfTotalIPs() uint64 {
	if x != nil {
		return x.PercentOfTotalIPs
	}
	return 0
}

var File_statistics_proto protoreflect.FileDescriptor

var file_statistics_proto_rawDesc = []byte{
	0x0a, 0x10, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0d, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xab, 0x01, 0x0a, 0x19, 0x53, 0x63, 0x61, 0x6e, 0x53,
	0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x07, 0x4a, 0x6f, 0x62, 0x54, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f,
	0x62, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x4a, 0x6f, 0x62, 0x54, 0x79, 0x70, 0x65, 0x12, 0x30,
	0x0a, 0x05, 0x41, 0x66, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x05, 0x41, 0x66, 0x74, 0x65, 0x72,
	0x12, 0x32, 0x0a, 0x06, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x06, 0x42, 0x65,
	0x66, 0x6f, 0x72, 0x65, 0x22, 0x49, 0x0a, 0x0e, 0x53, 0x63, 0x61, 0x6e, 0x53, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x12, 0x2f, 0x0a, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x69, 0x6e,
	0x67, 0x53, 0x63, 0x61, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x48,
	0x00, 0x52, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x42, 0x06, 0x0a, 0x04, 0x44, 0x61, 0x74, 0x61, 0x22,
	0xa0, 0x01, 0x0a, 0x10, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73,
	0x74, 0x69, 0x63, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x53, 0x63, 0x61,
	0x6e, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x53,
	0x63, 0x61, 0x6e, 0x73, 0x12, 0x28, 0x0a, 0x0f, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66,
	0x75, 0x6c, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x53,
	0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6c, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x12, 0x20,
	0x0a, 0x0b, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0b, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x53, 0x63, 0x61, 0x6e, 0x73,
	0x12, 0x20, 0x0a, 0x0b, 0x44, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x63, 0x74, 0x49, 0x50, 0x73, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x44, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x63, 0x74, 0x49,
	0x50, 0x73, 0x22, 0x45, 0x0a, 0x12, 0x50, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x61, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x12, 0x2f, 0x0a, 0x06, 0x43, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
	0x73, 0x52, 0x06, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x22, 0xaf, 0x01, 0x0a, 0x1d, 0x43, 0x6f,
	0x76, 0x65, 0x72, 0x61, 0x67, 0x65, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x07, 0x4a,
	0x6f, 0x62, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4a, 0x6f, 0x62, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x4a, 0x6f,
	0x62, 0x54, 0x79, 0x70, 0x65, 0x12, 0x30, 0x0a, 0x05, 0x41, 0x66, 0x74, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x05, 0x41, 0x66, 0x74, 0x65, 0x72, 0x12, 0x32, 0x0a, 0x06, 0x42, 0x65, 0x66, 0x6f, 0x72,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x06, 0x42, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x22, 0xb2, 0x01, 0x0a, 0x12,
	0x43, 0x6f, 0x76, 0x65, 0x72, 0x61, 0x67, 0x65, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69,
	0x63, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x53, 0x63, 0x61, 0x6e, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x53, 0x63, 0x61,
	0x6e, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x63, 0x74, 0x49, 0x50,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x44, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x63,
	0x74, 0x49, 0x50, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x50, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x4f,
	0x66, 0x53, 0x61, 0x76, 0x65, 0x64, 0x49, 0x50, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x11, 0x50, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x4f, 0x66, 0x53, 0x61, 0x76, 0x65, 0x64, 0x49,
	0x50, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x50, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x4f, 0x66, 0x54,
	0x6f, 0x74, 0x61, 0x6c, 0x49, 0x50, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x50,
	0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x4f, 0x66, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x49, 0x50, 0x73,
	0x42, 0x26, 0x5a, 0x24, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c,
	0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_statistics_proto_rawDescOnce sync.Once
	file_statistics_proto_rawDescData = file_statistics_proto_rawDesc
)

func file_statistics_proto_rawDescGZIP() []byte {
	file_statistics_proto_rawDescOnce.Do(func() {
		file_statistics_proto_rawDescData = protoimpl.X.CompressGZIP(file_statistics_proto_rawDescData)
	})
	return file_statistics_proto_rawDescData
}

var file_statistics_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_statistics_proto_goTypes = []any{
	(*ScanStatisticsQueryFilter)(nil),     // 0: proto.ScanStatisticsQueryFilter
	(*ScanStatistics)(nil),                // 1: proto.ScanStatistics
	(*CommonStatistics)(nil),              // 2: proto.CommonStatistics
	(*PingScanStatistics)(nil),            // 3: proto.PingScanStatistics
	(*CoverageStatisticsQueryFilter)(nil), // 4: proto.CoverageStatisticsQueryFilter
	(*CoverageStatistics)(nil),            // 5: proto.CoverageStatistics
	(JobType)(0),                          // 6: proto.JobType
	(*timestamppb.Timestamp)(nil),         // 7: google.protobuf.Timestamp
}
var file_statistics_proto_depIdxs = []int32{
	6, // 0: proto.ScanStatisticsQueryFilter.JobType:type_name -> proto.JobType
	7, // 1: proto.ScanStatisticsQueryFilter.After:type_name -> google.protobuf.Timestamp
	7, // 2: proto.ScanStatisticsQueryFilter.Before:type_name -> google.protobuf.Timestamp
	3, // 3: proto.ScanStatistics.Ping:type_name -> proto.PingScanStatistics
	2, // 4: proto.PingScanStatistics.Common:type_name -> proto.CommonStatistics
	6, // 5: proto.CoverageStatisticsQueryFilter.JobType:type_name -> proto.JobType
	7, // 6: proto.CoverageStatisticsQueryFilter.After:type_name -> google.protobuf.Timestamp
	7, // 7: proto.CoverageStatisticsQueryFilter.Before:type_name -> google.protobuf.Timestamp
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_statistics_proto_init() }
func file_statistics_proto_init() {
	if File_statistics_proto != nil {
		return
	}
	file_options_proto_init()
	file_statistics_proto_msgTypes[1].OneofWrappers = []any{
		(*ScanStatistics_Ping)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_statistics_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_statistics_proto_goTypes,
		DependencyIndexes: file_statistics_proto_depIdxs,
		MessageInfos:      file_statistics_proto_msgTypes,
	}.Build()
	File_statistics_proto = out.File
	file_statistics_proto_rawDesc = nil
	file_statistics_proto_goTypes = nil
	file_statistics_proto_depIdxs = nil
}
