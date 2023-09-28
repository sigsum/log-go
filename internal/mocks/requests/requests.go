// Code generated by MockGen. DO NOT EDIT.
// Source: sigsum.org/log-go/internal/requests (interfaces: TokenVerifier)

// Package token is a generated GoMock package.
package token

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	token "sigsum.org/sigsum-go/pkg/submit-token"
)

// MockTokenVerifier is a mock of TokenVerifier interface.
type MockTokenVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockTokenVerifierMockRecorder
}

// MockTokenVerifierMockRecorder is the mock recorder for MockTokenVerifier.
type MockTokenVerifierMockRecorder struct {
	mock *MockTokenVerifier
}

// NewMockTokenVerifier creates a new mock instance.
func NewMockTokenVerifier(ctrl *gomock.Controller) *MockTokenVerifier {
	mock := &MockTokenVerifier{ctrl: ctrl}
	mock.recorder = &MockTokenVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenVerifier) EXPECT() *MockTokenVerifierMockRecorder {
	return m.recorder
}

// Verify mocks base method.
func (m *MockTokenVerifier) Verify(arg0 context.Context, arg1 *token.SubmitHeader) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockTokenVerifierMockRecorder) Verify(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockTokenVerifier)(nil).Verify), arg0, arg1)
}