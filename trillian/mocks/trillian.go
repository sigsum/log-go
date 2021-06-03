// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/google/trillian (interfaces: TrillianLogClient)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	trillian "github.com/google/trillian"
	grpc "google.golang.org/grpc"
)

// MockTrillianLogClient is a mock of TrillianLogClient interface.
type MockTrillianLogClient struct {
	ctrl     *gomock.Controller
	recorder *MockTrillianLogClientMockRecorder
}

// MockTrillianLogClientMockRecorder is the mock recorder for MockTrillianLogClient.
type MockTrillianLogClientMockRecorder struct {
	mock *MockTrillianLogClient
}

// NewMockTrillianLogClient creates a new mock instance.
func NewMockTrillianLogClient(ctrl *gomock.Controller) *MockTrillianLogClient {
	mock := &MockTrillianLogClient{ctrl: ctrl}
	mock.recorder = &MockTrillianLogClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTrillianLogClient) EXPECT() *MockTrillianLogClientMockRecorder {
	return m.recorder
}

// AddSequencedLeaf mocks base method.
func (m *MockTrillianLogClient) AddSequencedLeaf(arg0 context.Context, arg1 *trillian.AddSequencedLeafRequest, arg2 ...grpc.CallOption) (*trillian.AddSequencedLeafResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddSequencedLeaf", varargs...)
	ret0, _ := ret[0].(*trillian.AddSequencedLeafResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddSequencedLeaf indicates an expected call of AddSequencedLeaf.
func (mr *MockTrillianLogClientMockRecorder) AddSequencedLeaf(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddSequencedLeaf", reflect.TypeOf((*MockTrillianLogClient)(nil).AddSequencedLeaf), varargs...)
}

// AddSequencedLeaves mocks base method.
func (m *MockTrillianLogClient) AddSequencedLeaves(arg0 context.Context, arg1 *trillian.AddSequencedLeavesRequest, arg2 ...grpc.CallOption) (*trillian.AddSequencedLeavesResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddSequencedLeaves", varargs...)
	ret0, _ := ret[0].(*trillian.AddSequencedLeavesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddSequencedLeaves indicates an expected call of AddSequencedLeaves.
func (mr *MockTrillianLogClientMockRecorder) AddSequencedLeaves(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddSequencedLeaves", reflect.TypeOf((*MockTrillianLogClient)(nil).AddSequencedLeaves), varargs...)
}

// GetConsistencyProof mocks base method.
func (m *MockTrillianLogClient) GetConsistencyProof(arg0 context.Context, arg1 *trillian.GetConsistencyProofRequest, arg2 ...grpc.CallOption) (*trillian.GetConsistencyProofResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetConsistencyProof", varargs...)
	ret0, _ := ret[0].(*trillian.GetConsistencyProofResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConsistencyProof indicates an expected call of GetConsistencyProof.
func (mr *MockTrillianLogClientMockRecorder) GetConsistencyProof(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConsistencyProof", reflect.TypeOf((*MockTrillianLogClient)(nil).GetConsistencyProof), varargs...)
}

// GetEntryAndProof mocks base method.
func (m *MockTrillianLogClient) GetEntryAndProof(arg0 context.Context, arg1 *trillian.GetEntryAndProofRequest, arg2 ...grpc.CallOption) (*trillian.GetEntryAndProofResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetEntryAndProof", varargs...)
	ret0, _ := ret[0].(*trillian.GetEntryAndProofResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEntryAndProof indicates an expected call of GetEntryAndProof.
func (mr *MockTrillianLogClientMockRecorder) GetEntryAndProof(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEntryAndProof", reflect.TypeOf((*MockTrillianLogClient)(nil).GetEntryAndProof), varargs...)
}

// GetInclusionProof mocks base method.
func (m *MockTrillianLogClient) GetInclusionProof(arg0 context.Context, arg1 *trillian.GetInclusionProofRequest, arg2 ...grpc.CallOption) (*trillian.GetInclusionProofResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetInclusionProof", varargs...)
	ret0, _ := ret[0].(*trillian.GetInclusionProofResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInclusionProof indicates an expected call of GetInclusionProof.
func (mr *MockTrillianLogClientMockRecorder) GetInclusionProof(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInclusionProof", reflect.TypeOf((*MockTrillianLogClient)(nil).GetInclusionProof), varargs...)
}

// GetInclusionProofByHash mocks base method.
func (m *MockTrillianLogClient) GetInclusionProofByHash(arg0 context.Context, arg1 *trillian.GetInclusionProofByHashRequest, arg2 ...grpc.CallOption) (*trillian.GetInclusionProofByHashResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetInclusionProofByHash", varargs...)
	ret0, _ := ret[0].(*trillian.GetInclusionProofByHashResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInclusionProofByHash indicates an expected call of GetInclusionProofByHash.
func (mr *MockTrillianLogClientMockRecorder) GetInclusionProofByHash(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInclusionProofByHash", reflect.TypeOf((*MockTrillianLogClient)(nil).GetInclusionProofByHash), varargs...)
}

// GetLatestSignedLogRoot mocks base method.
func (m *MockTrillianLogClient) GetLatestSignedLogRoot(arg0 context.Context, arg1 *trillian.GetLatestSignedLogRootRequest, arg2 ...grpc.CallOption) (*trillian.GetLatestSignedLogRootResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLatestSignedLogRoot", varargs...)
	ret0, _ := ret[0].(*trillian.GetLatestSignedLogRootResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestSignedLogRoot indicates an expected call of GetLatestSignedLogRoot.
func (mr *MockTrillianLogClientMockRecorder) GetLatestSignedLogRoot(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestSignedLogRoot", reflect.TypeOf((*MockTrillianLogClient)(nil).GetLatestSignedLogRoot), varargs...)
}

// GetLeavesByHash mocks base method.
func (m *MockTrillianLogClient) GetLeavesByHash(arg0 context.Context, arg1 *trillian.GetLeavesByHashRequest, arg2 ...grpc.CallOption) (*trillian.GetLeavesByHashResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLeavesByHash", varargs...)
	ret0, _ := ret[0].(*trillian.GetLeavesByHashResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeavesByHash indicates an expected call of GetLeavesByHash.
func (mr *MockTrillianLogClientMockRecorder) GetLeavesByHash(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeavesByHash", reflect.TypeOf((*MockTrillianLogClient)(nil).GetLeavesByHash), varargs...)
}

// GetLeavesByIndex mocks base method.
func (m *MockTrillianLogClient) GetLeavesByIndex(arg0 context.Context, arg1 *trillian.GetLeavesByIndexRequest, arg2 ...grpc.CallOption) (*trillian.GetLeavesByIndexResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLeavesByIndex", varargs...)
	ret0, _ := ret[0].(*trillian.GetLeavesByIndexResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeavesByIndex indicates an expected call of GetLeavesByIndex.
func (mr *MockTrillianLogClientMockRecorder) GetLeavesByIndex(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeavesByIndex", reflect.TypeOf((*MockTrillianLogClient)(nil).GetLeavesByIndex), varargs...)
}

// GetLeavesByRange mocks base method.
func (m *MockTrillianLogClient) GetLeavesByRange(arg0 context.Context, arg1 *trillian.GetLeavesByRangeRequest, arg2 ...grpc.CallOption) (*trillian.GetLeavesByRangeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLeavesByRange", varargs...)
	ret0, _ := ret[0].(*trillian.GetLeavesByRangeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeavesByRange indicates an expected call of GetLeavesByRange.
func (mr *MockTrillianLogClientMockRecorder) GetLeavesByRange(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeavesByRange", reflect.TypeOf((*MockTrillianLogClient)(nil).GetLeavesByRange), varargs...)
}

// GetSequencedLeafCount mocks base method.
func (m *MockTrillianLogClient) GetSequencedLeafCount(arg0 context.Context, arg1 *trillian.GetSequencedLeafCountRequest, arg2 ...grpc.CallOption) (*trillian.GetSequencedLeafCountResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetSequencedLeafCount", varargs...)
	ret0, _ := ret[0].(*trillian.GetSequencedLeafCountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSequencedLeafCount indicates an expected call of GetSequencedLeafCount.
func (mr *MockTrillianLogClientMockRecorder) GetSequencedLeafCount(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSequencedLeafCount", reflect.TypeOf((*MockTrillianLogClient)(nil).GetSequencedLeafCount), varargs...)
}

// InitLog mocks base method.
func (m *MockTrillianLogClient) InitLog(arg0 context.Context, arg1 *trillian.InitLogRequest, arg2 ...grpc.CallOption) (*trillian.InitLogResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "InitLog", varargs...)
	ret0, _ := ret[0].(*trillian.InitLogResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitLog indicates an expected call of InitLog.
func (mr *MockTrillianLogClientMockRecorder) InitLog(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitLog", reflect.TypeOf((*MockTrillianLogClient)(nil).InitLog), varargs...)
}

// QueueLeaf mocks base method.
func (m *MockTrillianLogClient) QueueLeaf(arg0 context.Context, arg1 *trillian.QueueLeafRequest, arg2 ...grpc.CallOption) (*trillian.QueueLeafResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueueLeaf", varargs...)
	ret0, _ := ret[0].(*trillian.QueueLeafResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueueLeaf indicates an expected call of QueueLeaf.
func (mr *MockTrillianLogClientMockRecorder) QueueLeaf(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueueLeaf", reflect.TypeOf((*MockTrillianLogClient)(nil).QueueLeaf), varargs...)
}

// QueueLeaves mocks base method.
func (m *MockTrillianLogClient) QueueLeaves(arg0 context.Context, arg1 *trillian.QueueLeavesRequest, arg2 ...grpc.CallOption) (*trillian.QueueLeavesResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueueLeaves", varargs...)
	ret0, _ := ret[0].(*trillian.QueueLeavesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueueLeaves indicates an expected call of QueueLeaves.
func (mr *MockTrillianLogClientMockRecorder) QueueLeaves(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueueLeaves", reflect.TypeOf((*MockTrillianLogClient)(nil).QueueLeaves), varargs...)
}
