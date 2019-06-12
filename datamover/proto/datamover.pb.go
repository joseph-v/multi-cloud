// Code generated by protoc-gen-go. DO NOT EDIT.
// source: datamover.proto

package datamover

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type KV struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KV) Reset()         { *m = KV{} }
func (m *KV) String() string { return proto.CompactTextString(m) }
func (*KV) ProtoMessage()    {}
func (*KV) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{0}
}
func (m *KV) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KV.Unmarshal(m, b)
}
func (m *KV) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KV.Marshal(b, m, deterministic)
}
func (dst *KV) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KV.Merge(dst, src)
}
func (m *KV) XXX_Size() int {
	return xxx_messageInfo_KV.Size(m)
}
func (m *KV) XXX_DiscardUnknown() {
	xxx_messageInfo_KV.DiscardUnknown(m)
}

var xxx_messageInfo_KV proto.InternalMessageInfo

func (m *KV) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KV) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type Filter struct {
	Prefix               string   `protobuf:"bytes,1,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Tag                  []*KV    `protobuf:"bytes,2,rep,name=tag,proto3" json:"tag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Filter) Reset()         { *m = Filter{} }
func (m *Filter) String() string { return proto.CompactTextString(m) }
func (*Filter) ProtoMessage()    {}
func (*Filter) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{1}
}
func (m *Filter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Filter.Unmarshal(m, b)
}
func (m *Filter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Filter.Marshal(b, m, deterministic)
}
func (dst *Filter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Filter.Merge(dst, src)
}
func (m *Filter) XXX_Size() int {
	return xxx_messageInfo_Filter.Size(m)
}
func (m *Filter) XXX_DiscardUnknown() {
	xxx_messageInfo_Filter.DiscardUnknown(m)
}

var xxx_messageInfo_Filter proto.InternalMessageInfo

func (m *Filter) GetPrefix() string {
	if m != nil {
		return m.Prefix
	}
	return ""
}

func (m *Filter) GetTag() []*KV {
	if m != nil {
		return m.Tag
	}
	return nil
}

type Connector struct {
	Type                 string   `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	BucketName           string   `protobuf:"bytes,2,opt,name=BucketName,proto3" json:"BucketName,omitempty"`
	ConnConfig           []*KV    `protobuf:"bytes,3,rep,name=ConnConfig,proto3" json:"ConnConfig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Connector) Reset()         { *m = Connector{} }
func (m *Connector) String() string { return proto.CompactTextString(m) }
func (*Connector) ProtoMessage()    {}
func (*Connector) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{2}
}
func (m *Connector) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Connector.Unmarshal(m, b)
}
func (m *Connector) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Connector.Marshal(b, m, deterministic)
}
func (dst *Connector) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Connector.Merge(dst, src)
}
func (m *Connector) XXX_Size() int {
	return xxx_messageInfo_Connector.Size(m)
}
func (m *Connector) XXX_DiscardUnknown() {
	xxx_messageInfo_Connector.DiscardUnknown(m)
}

var xxx_messageInfo_Connector proto.InternalMessageInfo

func (m *Connector) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *Connector) GetBucketName() string {
	if m != nil {
		return m.BucketName
	}
	return ""
}

func (m *Connector) GetConnConfig() []*KV {
	if m != nil {
		return m.ConnConfig
	}
	return nil
}

type RunJobRequest struct {
	Id                   string     `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	SourceConn           *Connector `protobuf:"bytes,2,opt,name=sourceConn,proto3" json:"sourceConn,omitempty"`
	DestConn             *Connector `protobuf:"bytes,3,opt,name=destConn,proto3" json:"destConn,omitempty"`
	Filt                 *Filter    `protobuf:"bytes,4,opt,name=filt,proto3" json:"filt,omitempty"`
	RemainSource         bool       `protobuf:"varint,5,opt,name=remainSource,proto3" json:"remainSource,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *RunJobRequest) Reset()         { *m = RunJobRequest{} }
func (m *RunJobRequest) String() string { return proto.CompactTextString(m) }
func (*RunJobRequest) ProtoMessage()    {}
func (*RunJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{3}
}
func (m *RunJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RunJobRequest.Unmarshal(m, b)
}
func (m *RunJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RunJobRequest.Marshal(b, m, deterministic)
}
func (dst *RunJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RunJobRequest.Merge(dst, src)
}
func (m *RunJobRequest) XXX_Size() int {
	return xxx_messageInfo_RunJobRequest.Size(m)
}
func (m *RunJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_RunJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_RunJobRequest proto.InternalMessageInfo

func (m *RunJobRequest) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *RunJobRequest) GetSourceConn() *Connector {
	if m != nil {
		return m.SourceConn
	}
	return nil
}

func (m *RunJobRequest) GetDestConn() *Connector {
	if m != nil {
		return m.DestConn
	}
	return nil
}

func (m *RunJobRequest) GetFilt() *Filter {
	if m != nil {
		return m.Filt
	}
	return nil
}

func (m *RunJobRequest) GetRemainSource() bool {
	if m != nil {
		return m.RemainSource
	}
	return false
}

type RunJobResponse struct {
	Err                  string   `protobuf:"bytes,1,opt,name=err,proto3" json:"err,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RunJobResponse) Reset()         { *m = RunJobResponse{} }
func (m *RunJobResponse) String() string { return proto.CompactTextString(m) }
func (*RunJobResponse) ProtoMessage()    {}
func (*RunJobResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{4}
}
func (m *RunJobResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RunJobResponse.Unmarshal(m, b)
}
func (m *RunJobResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RunJobResponse.Marshal(b, m, deterministic)
}
func (dst *RunJobResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RunJobResponse.Merge(dst, src)
}
func (m *RunJobResponse) XXX_Size() int {
	return xxx_messageInfo_RunJobResponse.Size(m)
}
func (m *RunJobResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_RunJobResponse.DiscardUnknown(m)
}

var xxx_messageInfo_RunJobResponse proto.InternalMessageInfo

func (m *RunJobResponse) GetErr() string {
	if m != nil {
		return m.Err
	}
	return ""
}

type LifecycleActionRequest struct {
	ObjKey               string   `protobuf:"bytes,1,opt,name=objKey,proto3" json:"objKey,omitempty"`
	BucketName           string   `protobuf:"bytes,2,opt,name=bucketName,proto3" json:"bucketName,omitempty"`
	Action               int32    `protobuf:"varint,3,opt,name=action,proto3" json:"action,omitempty"`
	SourceTier           int32    `protobuf:"varint,4,opt,name=sourceTier,proto3" json:"sourceTier,omitempty"`
	TargetTier           int32    `protobuf:"varint,5,opt,name=targetTier,proto3" json:"targetTier,omitempty"`
	SourceBackend        string   `protobuf:"bytes,6,opt,name=sourceBackend,proto3" json:"sourceBackend,omitempty"`
	TargetBackend        string   `protobuf:"bytes,7,opt,name=targetBackend,proto3" json:"targetBackend,omitempty"`
	ObjSize              int64    `protobuf:"varint,8,opt,name=objSize,proto3" json:"objSize,omitempty"`
	LastModified         int64    `protobuf:"varint,9,opt,name=lastModified,proto3" json:"lastModified,omitempty"`
	UploadId             string   `protobuf:"bytes,10,opt,name=uploadId,proto3" json:"uploadId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LifecycleActionRequest) Reset()         { *m = LifecycleActionRequest{} }
func (m *LifecycleActionRequest) String() string { return proto.CompactTextString(m) }
func (*LifecycleActionRequest) ProtoMessage()    {}
func (*LifecycleActionRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{5}
}
func (m *LifecycleActionRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LifecycleActionRequest.Unmarshal(m, b)
}
func (m *LifecycleActionRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LifecycleActionRequest.Marshal(b, m, deterministic)
}
func (dst *LifecycleActionRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LifecycleActionRequest.Merge(dst, src)
}
func (m *LifecycleActionRequest) XXX_Size() int {
	return xxx_messageInfo_LifecycleActionRequest.Size(m)
}
func (m *LifecycleActionRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LifecycleActionRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LifecycleActionRequest proto.InternalMessageInfo

func (m *LifecycleActionRequest) GetObjKey() string {
	if m != nil {
		return m.ObjKey
	}
	return ""
}

func (m *LifecycleActionRequest) GetBucketName() string {
	if m != nil {
		return m.BucketName
	}
	return ""
}

func (m *LifecycleActionRequest) GetAction() int32 {
	if m != nil {
		return m.Action
	}
	return 0
}

func (m *LifecycleActionRequest) GetSourceTier() int32 {
	if m != nil {
		return m.SourceTier
	}
	return 0
}

func (m *LifecycleActionRequest) GetTargetTier() int32 {
	if m != nil {
		return m.TargetTier
	}
	return 0
}

func (m *LifecycleActionRequest) GetSourceBackend() string {
	if m != nil {
		return m.SourceBackend
	}
	return ""
}

func (m *LifecycleActionRequest) GetTargetBackend() string {
	if m != nil {
		return m.TargetBackend
	}
	return ""
}

func (m *LifecycleActionRequest) GetObjSize() int64 {
	if m != nil {
		return m.ObjSize
	}
	return 0
}

func (m *LifecycleActionRequest) GetLastModified() int64 {
	if m != nil {
		return m.LastModified
	}
	return 0
}

func (m *LifecycleActionRequest) GetUploadId() string {
	if m != nil {
		return m.UploadId
	}
	return ""
}

type LifecycleActionResonse struct {
	Err                  string   `protobuf:"bytes,1,opt,name=err,proto3" json:"err,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LifecycleActionResonse) Reset()         { *m = LifecycleActionResonse{} }
func (m *LifecycleActionResonse) String() string { return proto.CompactTextString(m) }
func (*LifecycleActionResonse) ProtoMessage()    {}
func (*LifecycleActionResonse) Descriptor() ([]byte, []int) {
	return fileDescriptor_datamover_a96d9e6bb0d61e1a, []int{6}
}
func (m *LifecycleActionResonse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LifecycleActionResonse.Unmarshal(m, b)
}
func (m *LifecycleActionResonse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LifecycleActionResonse.Marshal(b, m, deterministic)
}
func (dst *LifecycleActionResonse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LifecycleActionResonse.Merge(dst, src)
}
func (m *LifecycleActionResonse) XXX_Size() int {
	return xxx_messageInfo_LifecycleActionResonse.Size(m)
}
func (m *LifecycleActionResonse) XXX_DiscardUnknown() {
	xxx_messageInfo_LifecycleActionResonse.DiscardUnknown(m)
}

var xxx_messageInfo_LifecycleActionResonse proto.InternalMessageInfo

func (m *LifecycleActionResonse) GetErr() string {
	if m != nil {
		return m.Err
	}
	return ""
}

func init() {
	proto.RegisterType((*KV)(nil), "KV")
	proto.RegisterType((*Filter)(nil), "Filter")
	proto.RegisterType((*Connector)(nil), "Connector")
	proto.RegisterType((*RunJobRequest)(nil), "RunJobRequest")
	proto.RegisterType((*RunJobResponse)(nil), "RunJobResponse")
	proto.RegisterType((*LifecycleActionRequest)(nil), "LifecycleActionRequest")
	proto.RegisterType((*LifecycleActionResonse)(nil), "LifecycleActionResonse")
}

func init() { proto.RegisterFile("datamover.proto", fileDescriptor_datamover_a96d9e6bb0d61e1a) }

var fileDescriptor_datamover_a96d9e6bb0d61e1a = []byte{
	// 494 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x53, 0xcd, 0x8e, 0xd3, 0x30,
	0x10, 0x26, 0x49, 0x9b, 0xb6, 0xb3, 0x6c, 0x17, 0x2c, 0x28, 0x56, 0x91, 0x50, 0x15, 0x10, 0xaa,
	0x16, 0x94, 0x43, 0x39, 0x70, 0x66, 0x17, 0x81, 0xa0, 0xc0, 0xc1, 0xbb, 0xda, 0xbb, 0x93, 0x4c,
	0x2b, 0xb7, 0x69, 0x5c, 0x1c, 0x67, 0x45, 0xb9, 0xf1, 0x4e, 0x3c, 0x07, 0xcf, 0x84, 0xec, 0xfc,
	0xb4, 0xd9, 0xed, 0x2d, 0xdf, 0xcf, 0xcc, 0xd8, 0xdf, 0xc4, 0x70, 0x96, 0x70, 0xcd, 0x37, 0xf2,
	0x16, 0x55, 0xb8, 0x55, 0x52, 0xcb, 0xe0, 0x2d, 0xb8, 0xf3, 0x1b, 0xf2, 0x08, 0xbc, 0x35, 0xee,
	0xa8, 0x33, 0x71, 0xa6, 0x03, 0x66, 0x3e, 0xc9, 0x13, 0xe8, 0xde, 0xf2, 0xb4, 0x40, 0xea, 0x5a,
	0xae, 0x04, 0xc1, 0x7b, 0xf0, 0x3f, 0x89, 0x54, 0xa3, 0x22, 0x23, 0xf0, 0xb7, 0x0a, 0x17, 0xe2,
	0x57, 0x55, 0x54, 0x21, 0xf2, 0x14, 0x3c, 0xcd, 0x97, 0xd4, 0x9d, 0x78, 0xd3, 0x93, 0x99, 0x17,
	0xce, 0x6f, 0x98, 0xc1, 0x41, 0x02, 0x83, 0x4b, 0x99, 0x65, 0x18, 0x6b, 0xa9, 0x08, 0x81, 0xce,
	0xf5, 0x6e, 0x8b, 0x55, 0xa5, 0xfd, 0x26, 0x2f, 0x00, 0x2e, 0x8a, 0x78, 0x8d, 0xfa, 0x07, 0xdf,
	0xd4, 0x43, 0x0f, 0x18, 0xf2, 0x12, 0xc0, 0x34, 0xb8, 0x94, 0xd9, 0x42, 0x2c, 0xa9, 0xb7, 0x6f,
	0x7f, 0x40, 0x07, 0x7f, 0x1d, 0x38, 0x65, 0x45, 0xf6, 0x55, 0x46, 0x0c, 0x7f, 0x16, 0x98, 0x6b,
	0x32, 0x04, 0x57, 0x24, 0xd5, 0x20, 0x57, 0x24, 0xe4, 0x1c, 0x20, 0x97, 0x85, 0x8a, 0xd1, 0x54,
	0xd9, 0x31, 0x27, 0x33, 0x08, 0x9b, 0xa3, 0xb1, 0x03, 0x95, 0xbc, 0x86, 0x7e, 0x82, 0xb9, 0xb6,
	0x4e, 0xef, 0x9e, 0xb3, 0xd1, 0xc8, 0x73, 0xe8, 0x2c, 0x44, 0xaa, 0x69, 0xc7, 0x7a, 0x7a, 0x61,
	0x99, 0x10, 0xb3, 0x24, 0x09, 0xe0, 0xa1, 0xc2, 0x0d, 0x17, 0xd9, 0x95, 0x6d, 0x4c, 0xbb, 0x13,
	0x67, 0xda, 0x67, 0x2d, 0x2e, 0x08, 0x60, 0x58, 0x9f, 0x3a, 0xdf, 0xca, 0x2c, 0x47, 0xb3, 0x0f,
	0x54, 0xaa, 0xde, 0x07, 0x2a, 0x15, 0xfc, 0x73, 0x61, 0xf4, 0x4d, 0x2c, 0x30, 0xde, 0xc5, 0x29,
	0x7e, 0x88, 0xb5, 0x90, 0x59, 0x7d, 0xc7, 0x11, 0xf8, 0x32, 0x5a, 0xcd, 0x9b, 0xfd, 0x55, 0xc8,
	0x44, 0x1a, 0xdd, 0x8b, 0x74, 0xcf, 0x98, 0x3a, 0x6e, 0x1b, 0xd9, 0xdb, 0x75, 0x59, 0x85, 0x4c,
	0x5d, 0x99, 0xc2, 0xb5, 0x40, 0x65, 0x6f, 0xd5, 0x65, 0x07, 0x8c, 0xd1, 0x35, 0x57, 0x4b, 0xd4,
	0x56, 0xef, 0x96, 0xfa, 0x9e, 0x21, 0xaf, 0xe0, 0xb4, 0x74, 0x5f, 0xf0, 0x78, 0x8d, 0x59, 0x42,
	0x7d, 0x3b, 0xba, 0x4d, 0x1a, 0x57, 0x59, 0x53, 0xbb, 0x7a, 0xa5, 0xab, 0x45, 0x12, 0x0a, 0x3d,
	0x19, 0xad, 0xae, 0xc4, 0x6f, 0xa4, 0xfd, 0x89, 0x33, 0xf5, 0x58, 0x0d, 0x4d, 0xb0, 0x29, 0xcf,
	0xf5, 0x77, 0x99, 0x88, 0x85, 0xc0, 0x84, 0x0e, 0xac, 0xdc, 0xe2, 0xc8, 0x18, 0xfa, 0xc5, 0x36,
	0x95, 0x3c, 0xf9, 0x92, 0x50, 0xb0, 0xed, 0x1b, 0x1c, 0x9c, 0x1f, 0xc9, 0x33, 0x3f, 0x1e, 0xfe,
	0xec, 0x8f, 0x03, 0x83, 0xe6, 0xe1, 0x90, 0x37, 0xe0, 0xb3, 0x22, 0x5b, 0xc9, 0x88, 0x0c, 0xc3,
	0xd6, 0xdf, 0x36, 0x3e, 0x0b, 0xdb, 0x7b, 0x0c, 0x1e, 0x90, 0xcf, 0xf0, 0xf8, 0xa3, 0xbc, 0x33,
	0x88, 0x3c, 0x0b, 0x8f, 0xaf, 0x72, 0x7c, 0x44, 0xc8, 0xcb, 0x46, 0x91, 0x6f, 0xdf, 0xeb, 0xbb,
	0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0xa4, 0xc8, 0x88, 0x2f, 0xc2, 0x03, 0x00, 0x00,
}
