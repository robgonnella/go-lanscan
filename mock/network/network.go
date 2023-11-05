// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/robgonnella/go-lanscan/pkg/network (interfaces: Network)
//
// Generated by this command:
//
//	mockgen -destination=../../mock/network/network.go -package=mock_network . Network
//
// Package mock_network is a generated GoMock package.
package mock_network

import (
	net "net"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockNetwork is a mock of Network interface.
type MockNetwork struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkMockRecorder
}

// MockNetworkMockRecorder is the mock recorder for MockNetwork.
type MockNetworkMockRecorder struct {
	mock *MockNetwork
}

// NewMockNetwork creates a new mock instance.
func NewMockNetwork(ctrl *gomock.Controller) *MockNetwork {
	mock := &MockNetwork{ctrl: ctrl}
	mock.recorder = &MockNetworkMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork) EXPECT() *MockNetworkMockRecorder {
	return m.recorder
}

// Cidr mocks base method.
func (m *MockNetwork) Cidr() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cidr")
	ret0, _ := ret[0].(string)
	return ret0
}

// Cidr indicates an expected call of Cidr.
func (mr *MockNetworkMockRecorder) Cidr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cidr", reflect.TypeOf((*MockNetwork)(nil).Cidr))
}

// Gateway mocks base method.
func (m *MockNetwork) Gateway() net.IP {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Gateway")
	ret0, _ := ret[0].(net.IP)
	return ret0
}

// Gateway indicates an expected call of Gateway.
func (mr *MockNetworkMockRecorder) Gateway() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Gateway", reflect.TypeOf((*MockNetwork)(nil).Gateway))
}

// Hostname mocks base method.
func (m *MockNetwork) Hostname() (*string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Hostname")
	ret0, _ := ret[0].(*string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Hostname indicates an expected call of Hostname.
func (mr *MockNetworkMockRecorder) Hostname() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Hostname", reflect.TypeOf((*MockNetwork)(nil).Hostname))
}

// IPNet mocks base method.
func (m *MockNetwork) IPNet() *net.IPNet {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IPNet")
	ret0, _ := ret[0].(*net.IPNet)
	return ret0
}

// IPNet indicates an expected call of IPNet.
func (mr *MockNetworkMockRecorder) IPNet() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IPNet", reflect.TypeOf((*MockNetwork)(nil).IPNet))
}

// Interface mocks base method.
func (m *MockNetwork) Interface() *net.Interface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Interface")
	ret0, _ := ret[0].(*net.Interface)
	return ret0
}

// Interface indicates an expected call of Interface.
func (mr *MockNetworkMockRecorder) Interface() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Interface", reflect.TypeOf((*MockNetwork)(nil).Interface))
}

// UserIP mocks base method.
func (m *MockNetwork) UserIP() net.IP {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserIP")
	ret0, _ := ret[0].(net.IP)
	return ret0
}

// UserIP indicates an expected call of UserIP.
func (mr *MockNetworkMockRecorder) UserIP() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserIP", reflect.TypeOf((*MockNetwork)(nil).UserIP))
}
