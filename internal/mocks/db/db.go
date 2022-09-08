// Code generated by MockGen. DO NOT EDIT.
// Source: sigsum.org/log-go/internal/db (interfaces: Client)

// Package db is a generated GoMock package.
package db

import (
	context "context"
	reflect "reflect"

	requests "sigsum.org/sigsum-go/pkg/requests"
	types "sigsum.org/sigsum-go/pkg/types"
	gomock "github.com/golang/mock/gomock"
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

// AddLeaf mocks base method.
func (m *MockClient) AddLeaf(arg0 context.Context, arg1 *requests.Leaf, arg2 uint64) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddLeaf", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddLeaf indicates an expected call of AddLeaf.
func (mr *MockClientMockRecorder) AddLeaf(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddLeaf", reflect.TypeOf((*MockClient)(nil).AddLeaf), arg0, arg1, arg2)
}

// AddSequencedLeaves mocks base method.
func (m *MockClient) AddSequencedLeaves(arg0 context.Context, arg1 types.Leaves, arg2 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddSequencedLeaves", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddSequencedLeaves indicates an expected call of AddSequencedLeaves.
func (mr *MockClientMockRecorder) AddSequencedLeaves(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddSequencedLeaves", reflect.TypeOf((*MockClient)(nil).AddSequencedLeaves), arg0, arg1, arg2)
}

// GetConsistencyProof mocks base method.
func (m *MockClient) GetConsistencyProof(arg0 context.Context, arg1 *requests.ConsistencyProof) (*types.ConsistencyProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConsistencyProof", arg0, arg1)
	ret0, _ := ret[0].(*types.ConsistencyProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConsistencyProof indicates an expected call of GetConsistencyProof.
func (mr *MockClientMockRecorder) GetConsistencyProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConsistencyProof", reflect.TypeOf((*MockClient)(nil).GetConsistencyProof), arg0, arg1)
}

// GetInclusionProof mocks base method.
func (m *MockClient) GetInclusionProof(arg0 context.Context, arg1 *requests.InclusionProof) (*types.InclusionProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInclusionProof", arg0, arg1)
	ret0, _ := ret[0].(*types.InclusionProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInclusionProof indicates an expected call of GetInclusionProof.
func (mr *MockClientMockRecorder) GetInclusionProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInclusionProof", reflect.TypeOf((*MockClient)(nil).GetInclusionProof), arg0, arg1)
}

// GetLeaves mocks base method.
func (m *MockClient) GetLeaves(arg0 context.Context, arg1 *requests.Leaves) (*types.Leaves, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLeaves", arg0, arg1)
	ret0, _ := ret[0].(*types.Leaves)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeaves indicates an expected call of GetLeaves.
func (mr *MockClientMockRecorder) GetLeaves(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeaves", reflect.TypeOf((*MockClient)(nil).GetLeaves), arg0, arg1)
}

// GetTreeHead mocks base method.
func (m *MockClient) GetTreeHead(arg0 context.Context) (*types.TreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTreeHead", arg0)
	ret0, _ := ret[0].(*types.TreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTreeHead indicates an expected call of GetTreeHead.
func (mr *MockClientMockRecorder) GetTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTreeHead", reflect.TypeOf((*MockClient)(nil).GetTreeHead), arg0)
}
