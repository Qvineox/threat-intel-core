// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v4.25.3
// source: fleet.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

type BotType int32

const (
	BotType_BOT_PING BotType = 0
)

// Enum value maps for BotType.
var (
	BotType_name = map[int32]string{
		0: "BOT_PING",
	}
	BotType_value = map[string]int32{
		"BOT_PING": 0,
	}
)

func (x BotType) Enum() *BotType {
	p := new(BotType)
	*p = x
	return p
}

func (x BotType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (BotType) Descriptor() protoreflect.EnumDescriptor {
	return file_fleet_proto_enumTypes[0].Descriptor()
}

func (BotType) Type() protoreflect.EnumType {
	return &file_fleet_proto_enumTypes[0]
}

func (x BotType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use BotType.Descriptor instead.
func (BotType) EnumDescriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{0}
}

type FleetQueryFilter struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ActiveOnly    bool                   `protobuf:"varint,1,opt,name=ActiveOnly,proto3" json:"ActiveOnly,omitempty"`
	ShowTypes     []BotType              `protobuf:"varint,2,rep,packed,name=ShowTypes,proto3,enum=proto.BotType" json:"ShowTypes,omitempty"`
	ClusterUUID   *string                `protobuf:"bytes,3,opt,name=ClusterUUID,proto3,oneof" json:"ClusterUUID,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FleetQueryFilter) Reset() {
	*x = FleetQueryFilter{}
	mi := &file_fleet_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FleetQueryFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FleetQueryFilter) ProtoMessage() {}

func (x *FleetQueryFilter) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FleetQueryFilter.ProtoReflect.Descriptor instead.
func (*FleetQueryFilter) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{0}
}

func (x *FleetQueryFilter) GetActiveOnly() bool {
	if x != nil {
		return x.ActiveOnly
	}
	return false
}

func (x *FleetQueryFilter) GetShowTypes() []BotType {
	if x != nil {
		return x.ShowTypes
	}
	return nil
}

func (x *FleetQueryFilter) GetClusterUUID() string {
	if x != nil && x.ClusterUUID != nil {
		return *x.ClusterUUID
	}
	return ""
}

// Fleet describes all bots and coordinators in a system
type Fleet struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Bots          []*Bot                 `protobuf:"bytes,1,rep,name=Bots,proto3" json:"Bots,omitempty"`
	Collectors    []*Collector           `protobuf:"bytes,2,rep,name=Collectors,proto3" json:"Collectors,omitempty"`
	Clusters      []*Cluster             `protobuf:"bytes,3,rep,name=Clusters,proto3" json:"Clusters,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Fleet) Reset() {
	*x = Fleet{}
	mi := &file_fleet_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Fleet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Fleet) ProtoMessage() {}

func (x *Fleet) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Fleet.ProtoReflect.Descriptor instead.
func (*Fleet) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{1}
}

func (x *Fleet) GetBots() []*Bot {
	if x != nil {
		return x.Bots
	}
	return nil
}

func (x *Fleet) GetCollectors() []*Collector {
	if x != nil {
		return x.Collectors
	}
	return nil
}

func (x *Fleet) GetClusters() []*Cluster {
	if x != nil {
		return x.Clusters
	}
	return nil
}

type Bot struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Identity      string                 `protobuf:"bytes,1,opt,name=Identity,proto3" json:"Identity,omitempty"`
	Type          BotType                `protobuf:"varint,2,opt,name=Type,proto3,enum=proto.BotType" json:"Type,omitempty"`
	State         *BotState              `protobuf:"bytes,3,opt,name=State,proto3" json:"State,omitempty"`
	ClusterUUID   string                 `protobuf:"bytes,4,opt,name=ClusterUUID,proto3" json:"ClusterUUID,omitempty"`
	CreatedAt     *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty"`
	LastCheckAt   *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=LastCheckAt,proto3" json:"LastCheckAt,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Bot) Reset() {
	*x = Bot{}
	mi := &file_fleet_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Bot) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bot) ProtoMessage() {}

func (x *Bot) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bot.ProtoReflect.Descriptor instead.
func (*Bot) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{2}
}

func (x *Bot) GetIdentity() string {
	if x != nil {
		return x.Identity
	}
	return ""
}

func (x *Bot) GetType() BotType {
	if x != nil {
		return x.Type
	}
	return BotType_BOT_PING
}

func (x *Bot) GetState() *BotState {
	if x != nil {
		return x.State
	}
	return nil
}

func (x *Bot) GetClusterUUID() string {
	if x != nil {
		return x.ClusterUUID
	}
	return ""
}

func (x *Bot) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Bot) GetLastCheckAt() *timestamppb.Timestamp {
	if x != nil {
		return x.LastCheckAt
	}
	return nil
}

type BotState struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	IsActive          bool                   `protobuf:"varint,1,opt,name=IsActive,proto3" json:"IsActive,omitempty"`
	IsBusy            bool                   `protobuf:"varint,2,opt,name=IsBusy,proto3" json:"IsBusy,omitempty"`
	CurrentScanOption *string                `protobuf:"bytes,3,opt,name=CurrentScanOption,proto3,oneof" json:"CurrentScanOption,omitempty"`
	TasksLeft         uint64                 `protobuf:"varint,4,opt,name=TasksLeft,proto3" json:"TasksLeft,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *BotState) Reset() {
	*x = BotState{}
	mi := &file_fleet_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BotState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BotState) ProtoMessage() {}

func (x *BotState) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BotState.ProtoReflect.Descriptor instead.
func (*BotState) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{3}
}

func (x *BotState) GetIsActive() bool {
	if x != nil {
		return x.IsActive
	}
	return false
}

func (x *BotState) GetIsBusy() bool {
	if x != nil {
		return x.IsBusy
	}
	return false
}

func (x *BotState) GetCurrentScanOption() string {
	if x != nil && x.CurrentScanOption != nil {
		return *x.CurrentScanOption
	}
	return ""
}

func (x *BotState) GetTasksLeft() uint64 {
	if x != nil {
		return x.TasksLeft
	}
	return 0
}

type BotToken struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	JWT           string                 `protobuf:"bytes,1,opt,name=JWT,proto3" json:"JWT,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BotToken) Reset() {
	*x = BotToken{}
	mi := &file_fleet_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BotToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BotToken) ProtoMessage() {}

func (x *BotToken) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BotToken.ProtoReflect.Descriptor instead.
func (*BotToken) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{4}
}

func (x *BotToken) GetJWT() string {
	if x != nil {
		return x.JWT
	}
	return ""
}

type Collector struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Identity      string                 `protobuf:"bytes,1,opt,name=Identity,proto3" json:"Identity,omitempty"`
	IsActive      bool                   `protobuf:"varint,3,opt,name=IsActive,proto3" json:"IsActive,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Collector) Reset() {
	*x = Collector{}
	mi := &file_fleet_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Collector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Collector) ProtoMessage() {}

func (x *Collector) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Collector.ProtoReflect.Descriptor instead.
func (*Collector) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{5}
}

func (x *Collector) GetIdentity() string {
	if x != nil {
		return x.Identity
	}
	return ""
}

func (x *Collector) GetIsActive() bool {
	if x != nil {
		return x.IsActive
	}
	return false
}

type Cluster struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            uint64                 `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	Description   string                 `protobuf:"bytes,3,opt,name=Description,proto3" json:"Description,omitempty"`
	IsActive      bool                   `protobuf:"varint,4,opt,name=IsActive,proto3" json:"IsActive,omitempty"`
	Token         *BotToken              `protobuf:"bytes,5,opt,name=Token,proto3,oneof" json:"Token,omitempty"`
	CreatedAt     *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty"`
	UpdatedAt     *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=UpdatedAt,proto3" json:"UpdatedAt,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Cluster) Reset() {
	*x = Cluster{}
	mi := &file_fleet_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Cluster) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Cluster) ProtoMessage() {}

func (x *Cluster) ProtoReflect() protoreflect.Message {
	mi := &file_fleet_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Cluster.ProtoReflect.Descriptor instead.
func (*Cluster) Descriptor() ([]byte, []int) {
	return file_fleet_proto_rawDescGZIP(), []int{6}
}

func (x *Cluster) GetID() uint64 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *Cluster) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Cluster) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Cluster) GetIsActive() bool {
	if x != nil {
		return x.IsActive
	}
	return false
}

func (x *Cluster) GetToken() *BotToken {
	if x != nil {
		return x.Token
	}
	return nil
}

func (x *Cluster) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Cluster) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

var File_fleet_proto protoreflect.FileDescriptor

var file_fleet_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x66, 0x6c, 0x65, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x97, 0x01, 0x0a, 0x10, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x1e, 0x0a, 0x0a, 0x41, 0x63,
	0x74, 0x69, 0x76, 0x65, 0x4f, 0x6e, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a,
	0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x2c, 0x0a, 0x09, 0x53, 0x68,
	0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x0e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6f, 0x74, 0x54, 0x79, 0x70, 0x65, 0x52, 0x09, 0x53,
	0x68, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x0b, 0x43, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x55, 0x55, 0x49, 0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x55, 0x55, 0x49, 0x44, 0x88, 0x01, 0x01, 0x42,
	0x0e, 0x0a, 0x0c, 0x5f, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x55, 0x55, 0x49, 0x44, 0x22,
	0x85, 0x01, 0x0a, 0x05, 0x46, 0x6c, 0x65, 0x65, 0x74, 0x12, 0x1e, 0x0a, 0x04, 0x42, 0x6f, 0x74,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x42, 0x6f, 0x74, 0x52, 0x04, 0x42, 0x6f, 0x74, 0x73, 0x12, 0x30, 0x0a, 0x0a, 0x43, 0x6f, 0x6c,
	0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52,
	0x0a, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x12, 0x2a, 0x0a, 0x08, 0x43,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x52, 0x08, 0x43,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x22, 0x86, 0x02, 0x0a, 0x03, 0x42, 0x6f, 0x74, 0x12,
	0x1a, 0x0a, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x22, 0x0a, 0x04, 0x54,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x42, 0x6f, 0x74, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x25, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6f, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52,
	0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x55, 0x55, 0x49, 0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x43, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x55, 0x55, 0x49, 0x44, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x41, 0x74, 0x12, 0x3c, 0x0a, 0x0b, 0x4c, 0x61, 0x73, 0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x41,
	0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0b, 0x4c, 0x61, 0x73, 0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x41, 0x74,
	0x22, 0xa5, 0x01, 0x0a, 0x08, 0x42, 0x6f, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1a, 0x0a,
	0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x73, 0x42,
	0x75, 0x73, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x49, 0x73, 0x42, 0x75, 0x73,
	0x79, 0x12, 0x31, 0x0a, 0x11, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x63, 0x61, 0x6e,
	0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x11,
	0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x88, 0x01, 0x01, 0x12, 0x1c, 0x0a, 0x09, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x4c, 0x65, 0x66,
	0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x54, 0x61, 0x73, 0x6b, 0x73, 0x4c, 0x65,
	0x66, 0x74, 0x42, 0x14, 0x0a, 0x12, 0x5f, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x63,
	0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x1c, 0x0a, 0x08, 0x42, 0x6f, 0x74, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x4a, 0x57, 0x54, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x4a, 0x57, 0x54, 0x22, 0x43, 0x0a, 0x09, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12,
	0x1a, 0x0a, 0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x22, 0x95, 0x02, 0x0a, 0x07,
	0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x02, 0x49, 0x44, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x44,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1a, 0x0a,
	0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x08, 0x49, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x12, 0x2a, 0x0a, 0x05, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x42, 0x6f, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x48, 0x00, 0x52, 0x05, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x38, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x41, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x38, 0x0a, 0x09, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x2a, 0x17, 0x0a, 0x07, 0x42, 0x6f, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0c,
	0x0a, 0x08, 0x42, 0x4f, 0x54, 0x5f, 0x50, 0x49, 0x4e, 0x47, 0x10, 0x00, 0x42, 0x26, 0x5a, 0x24,
	0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2d, 0x63, 0x6f, 0x72,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_fleet_proto_rawDescOnce sync.Once
	file_fleet_proto_rawDescData = file_fleet_proto_rawDesc
)

func file_fleet_proto_rawDescGZIP() []byte {
	file_fleet_proto_rawDescOnce.Do(func() {
		file_fleet_proto_rawDescData = protoimpl.X.CompressGZIP(file_fleet_proto_rawDescData)
	})
	return file_fleet_proto_rawDescData
}

var file_fleet_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_fleet_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_fleet_proto_goTypes = []any{
	(BotType)(0),                  // 0: proto.BotType
	(*FleetQueryFilter)(nil),      // 1: proto.FleetQueryFilter
	(*Fleet)(nil),                 // 2: proto.Fleet
	(*Bot)(nil),                   // 3: proto.Bot
	(*BotState)(nil),              // 4: proto.BotState
	(*BotToken)(nil),              // 5: proto.BotToken
	(*Collector)(nil),             // 6: proto.Collector
	(*Cluster)(nil),               // 7: proto.Cluster
	(*timestamppb.Timestamp)(nil), // 8: google.protobuf.Timestamp
}
var file_fleet_proto_depIdxs = []int32{
	0,  // 0: proto.FleetQueryFilter.ShowTypes:type_name -> proto.BotType
	3,  // 1: proto.Fleet.Bots:type_name -> proto.Bot
	6,  // 2: proto.Fleet.Collectors:type_name -> proto.Collector
	7,  // 3: proto.Fleet.Clusters:type_name -> proto.Cluster
	0,  // 4: proto.Bot.Type:type_name -> proto.BotType
	4,  // 5: proto.Bot.State:type_name -> proto.BotState
	8,  // 6: proto.Bot.CreatedAt:type_name -> google.protobuf.Timestamp
	8,  // 7: proto.Bot.LastCheckAt:type_name -> google.protobuf.Timestamp
	5,  // 8: proto.Cluster.Token:type_name -> proto.BotToken
	8,  // 9: proto.Cluster.CreatedAt:type_name -> google.protobuf.Timestamp
	8,  // 10: proto.Cluster.UpdatedAt:type_name -> google.protobuf.Timestamp
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_fleet_proto_init() }
func file_fleet_proto_init() {
	if File_fleet_proto != nil {
		return
	}
	file_fleet_proto_msgTypes[0].OneofWrappers = []any{}
	file_fleet_proto_msgTypes[3].OneofWrappers = []any{}
	file_fleet_proto_msgTypes[6].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_fleet_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_fleet_proto_goTypes,
		DependencyIndexes: file_fleet_proto_depIdxs,
		EnumInfos:         file_fleet_proto_enumTypes,
		MessageInfos:      file_fleet_proto_msgTypes,
	}.Build()
	File_fleet_proto = out.File
	file_fleet_proto_rawDesc = nil
	file_fleet_proto_goTypes = nil
	file_fleet_proto_depIdxs = nil
}
