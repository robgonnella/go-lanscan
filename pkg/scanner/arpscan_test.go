// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/google/gopacket"
	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	mock_vendor "github.com/robgonnella/go-lanscan/mock/vendor"
	test_helper "github.com/robgonnella/go-lanscan/pkg/internal/test-helper"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/robgonnella/go-lanscan/pkg/vendor"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestArpScanner(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockInterface := &net.Interface{
		Name:         "interfaceName",
		HardwareAddr: net.HardwareAddr([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
	}

	_, mockIPNet, _ := net.ParseCIDR("172.17.1.1/32")

	mockUserIP := net.ParseIP("172.17.1.1")
	mockNonIncludedArpSrcIP := net.ParseIP("172.17.1.2")
	mockIncludedArpSrcIP := net.ParseIP("172.17.1.1")

	t.Run("returns immediately if already scanning", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}

		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockNonIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		go arpScanner.Scan()

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("returns error if PacketCapture.OpenLive return error", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		mockErr := errors.New("mock open-live error")

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(nil, mockErr)

		err := arpScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("performs arp scan on default network info", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockNonIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("performs arp scan on provided targets", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockNonIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("ignores non arp reply packets", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpRequestReadResult()
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("ignores arp reply packets that originate from scanning host", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockNonIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // scanning host hw address
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("process valid arp reply packet", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("process valid arp reply packet and includes vendor info", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
			scanner.WithVendorInfo(true),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		vendorRepo.EXPECT().Query(gomock.Any()).AnyTimes().Return(
			&vendor.VendorResult{
				Name: "Apple",
			},
			nil,
		)

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("handles vendor query error", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
			scanner.WithVendorInfo(true),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		vendorRepo.EXPECT().Query(gomock.Any()).AnyTimes().Return(
			nil,
			errors.New("mock vendor query error"),
		)

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("calls request notification callback", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		callback := func(request *scanner.Request) {
			assert.NotNil(st, request)
		}

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
			scanner.WithRequestNotifications(callback),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				arpScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		vendorRepo.EXPECT().Query(gomock.Any()).AnyTimes().Return(
			nil,
			errors.New("mock vendor query error"),
		)

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("handles serialize layers error", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		callback := func(request *scanner.Request) {
			assert.NotNil(st, request)
		}

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
			scanner.WithRequestNotifications(callback),
		)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).
			AnyTimes().
			Return(errors.New("mock serialize layers error"))

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		assert.Error(st, err)
	})

	t.Run("handles write packet data error", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		callback := func(request *scanner.Request) {
			assert.NotNil(st, request)
		}

		resultChan := make(chan *scanner.ScanResult)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			resultChan,
			vendorRepo,
			scanner.WithPacketCapture(cap),
			scanner.WithRequestNotifications(callback),
		)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return errors.New("mock write packet data error")
		})

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		assert.Error(st, err)
	})
}
