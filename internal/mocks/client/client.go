// Code generated by MockGen. DO NOT EDIT.
// Source: sigsum.org/sigsum-go/pkg/client (interfaces: Client)

// Package client is a generated GoMock package.
package client

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	requests "sigsum.org/sigsum-go/pkg/requests"
	types "sigsum.org/sigsum-go/pkg/types"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AddCosignature mocks base method.
func (m *MockClient) AddCosignature(arg0 context.Context, arg1 requests.Cosignature) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCosignature", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCosignature indicates an expected call of AddCosignature.
func (mr *MockClientMockRecorder) AddCosignature(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCosignature", reflect.TypeOf((*MockClient)(nil).AddCosignature), arg0, arg1)
}

// AddLeaf mocks base method.
func (m *MockClient) AddLeaf(arg0 context.Context, arg1 requests.Leaf) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddLeaf", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddLeaf indicates an expected call of AddLeaf.
func (mr *MockClientMockRecorder) AddLeaf(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddLeaf", reflect.TypeOf((*MockClient)(nil).AddLeaf), arg0, arg1)
}

// GetConsistencyProof mocks base method.
func (m *MockClient) GetConsistencyProof(arg0 context.Context, arg1 requests.ConsistencyProof) (types.ConsistencyProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConsistencyProof", arg0, arg1)
	ret0, _ := ret[0].(types.ConsistencyProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConsistencyProof indicates an expected call of GetConsistencyProof.
func (mr *MockClientMockRecorder) GetConsistencyProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConsistencyProof", reflect.TypeOf((*MockClient)(nil).GetConsistencyProof), arg0, arg1)
}

// GetCosignedTreeHead mocks base method.
func (m *MockClient) GetCosignedTreeHead(arg0 context.Context) (types.CosignedTreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCosignedTreeHead", arg0)
	ret0, _ := ret[0].(types.CosignedTreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCosignedTreeHead indicates an expected call of GetCosignedTreeHead.
func (mr *MockClientMockRecorder) GetCosignedTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCosignedTreeHead", reflect.TypeOf((*MockClient)(nil).GetCosignedTreeHead), arg0)
}

// GetInclusionProof mocks base method.
func (m *MockClient) GetInclusionProof(arg0 context.Context, arg1 requests.InclusionProof) (types.InclusionProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInclusionProof", arg0, arg1)
	ret0, _ := ret[0].(types.InclusionProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInclusionProof indicates an expected call of GetInclusionProof.
func (mr *MockClientMockRecorder) GetInclusionProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInclusionProof", reflect.TypeOf((*MockClient)(nil).GetInclusionProof), arg0, arg1)
}

// GetLeaves mocks base method.
func (m *MockClient) GetLeaves(arg0 context.Context, arg1 requests.Leaves) (types.Leaves, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLeaves", arg0, arg1)
	ret0, _ := ret[0].(types.Leaves)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeaves indicates an expected call of GetLeaves.
func (mr *MockClientMockRecorder) GetLeaves(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeaves", reflect.TypeOf((*MockClient)(nil).GetLeaves), arg0, arg1)
}

// GetToCosignTreeHead mocks base method.
func (m *MockClient) GetToCosignTreeHead(arg0 context.Context) (types.SignedTreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToCosignTreeHead", arg0)
	ret0, _ := ret[0].(types.SignedTreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetToCosignTreeHead indicates an expected call of GetToCosignTreeHead.
func (mr *MockClientMockRecorder) GetToCosignTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToCosignTreeHead", reflect.TypeOf((*MockClient)(nil).GetToCosignTreeHead), arg0)
}

// GetUnsignedTreeHead mocks base method.
func (m *MockClient) GetUnsignedTreeHead(arg0 context.Context) (types.TreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUnsignedTreeHead", arg0)
	ret0, _ := ret[0].(types.TreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUnsignedTreeHead indicates an expected call of GetUnsignedTreeHead.
func (mr *MockClientMockRecorder) GetUnsignedTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUnsignedTreeHead", reflect.TypeOf((*MockClient)(nil).GetUnsignedTreeHead), arg0)
}

// Initiated mocks base method.
func (m *MockClient) Initiated() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Initiated")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Initiated indicates an expected call of Initiated.
func (mr *MockClientMockRecorder) Initiated() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initiated", reflect.TypeOf((*MockClient)(nil).Initiated))
}
