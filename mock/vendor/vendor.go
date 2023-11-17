// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/robgonnella/go-lanscan/pkg/vendor (interfaces: VendorRepo)
//
// Generated by this command:
//
//	mockgen -destination=../../mock/vendor/vendor.go -package=mock_vendor . VendorRepo
//
// Package mock_vendor is a generated GoMock package.
package mock_vendor

import (
	net "net"
	reflect "reflect"

	vendor "github.com/robgonnella/go-lanscan/pkg/vendor"
	gomock "go.uber.org/mock/gomock"
)

// MockVendorRepo is a mock of VendorRepo interface.
type MockVendorRepo struct {
	ctrl     *gomock.Controller
	recorder *MockVendorRepoMockRecorder
}

// MockVendorRepoMockRecorder is the mock recorder for MockVendorRepo.
type MockVendorRepoMockRecorder struct {
	mock *MockVendorRepo
}

// NewMockVendorRepo creates a new mock instance.
func NewMockVendorRepo(ctrl *gomock.Controller) *MockVendorRepo {
	mock := &MockVendorRepo{ctrl: ctrl}
	mock.recorder = &MockVendorRepoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVendorRepo) EXPECT() *MockVendorRepoMockRecorder {
	return m.recorder
}

// Query mocks base method.
func (m *MockVendorRepo) Query(arg0 net.HardwareAddr) (*vendor.VendorResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Query", arg0)
	ret0, _ := ret[0].(*vendor.VendorResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query.
func (mr *MockVendorRepoMockRecorder) Query(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockVendorRepo)(nil).Query), arg0)
}

// UpdateVendors mocks base method.
func (m *MockVendorRepo) UpdateVendors() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateVendors")
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateVendors indicates an expected call of UpdateVendors.
func (mr *MockVendorRepoMockRecorder) UpdateVendors() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateVendors", reflect.TypeOf((*MockVendorRepo)(nil).UpdateVendors))
}