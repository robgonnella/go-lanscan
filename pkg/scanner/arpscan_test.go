// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_oui "github.com/robgonnella/go-lanscan/mock/oui"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	test_helper "github.com/robgonnella/go-lanscan/pkg/internal/test-helper"
	"github.com/robgonnella/go-lanscan/pkg/oui"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
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

	cidr := "172.17.1.1/32"
	_, mockIPNet, _ := net.ParseCIDR(cidr)

	mockUserIP := net.ParseIP("172.17.1.1")
	mockNonIncludedArpSrcIP := net.ParseIP("172.17.1.2")
	mockIncludedArpSrcIP := net.ParseIP("172.17.1.1")

	t.Run("returns immediately if already scanning", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				time.AfterFunc(time.Millisecond*500, arpScanner.Stop)
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

		assert.NoError(st, err)
	})

	t.Run("returns error if PacketCapture.OpenLive return error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		mockErr := errors.New("mock open-live error")

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(nil, mockErr)

		err := arpScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("prints debug message if reading packets returns error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP)
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		firstCall := true
		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if firstCall {
				firstCall = false
				return nil, gopacket.CaptureInfo{}, errors.New("mock ReadPacketData error")
			}
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewArpReplyReadResult(
				mockNonIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("performs arp scan on default network info", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP)
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
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
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
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
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewArpRequestReadResult()
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("ignores arp reply packets that originate from scanning host", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
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
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
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
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_oui.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		vendorRepo.EXPECT().UpdateVendors().Times(1)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
			scanner.WithVendorInfo(vendorRepo),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		vendorRepo.EXPECT().Query(gomock.Any()).AnyTimes().Return(
			&oui.VendorResult{
				Name: "Apple",
			},
			nil,
		)

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("handles vendor query error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		vendorRepo := mock_oui.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		vendorRepo.EXPECT().UpdateVendors().Times(1)

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
			scanner.WithVendorInfo(vendorRepo),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
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

	t.Run("panics if fails to update static vendors", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		vendorRepo := mock_oui.NewMockVendorRepo(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		vendorRepo.EXPECT().UpdateVendors().Return(errors.New("mock update vendors error"))

		panicTestFunc := func() {
			scanner.NewArpScanner(
				[]string{"172.17.1.1"},
				mockNetInfo,
				scanner.WithPacketCapture(capture),
				scanner.WithVendorInfo(vendorRepo),
			)
		}

		assert.Panics(st, panicTestFunc)
	})

	t.Run("sends request notifications", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		requestNotifier := make(chan *scanner.Request)

		go func() {
			r := <-requestNotifier
			assert.NotNil(st, r)
		}()

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
			scanner.WithRequestNotifications(requestNotifier),
		)

		wg := sync.WaitGroup{}
		wg.Add(1)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					arpScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewArpReplyReadResult(
				mockIncludedArpSrcIP,
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			)
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("handles serialize layers error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		requestNotifier := make(chan *scanner.Request)

		go func() {
			r := <-requestNotifier
			assert.NotNil(st, r)
		}()

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
			scanner.WithRequestNotifications(requestNotifier),
		)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(
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
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		mockNetInfo := mock_network.NewMockNetwork(ctrl)

		requestNotifier := make(chan *scanner.Request)

		go func() {
			r := <-requestNotifier
			assert.NotNil(st, r)
		}()

		arpScanner := scanner.NewArpScanner(
			[]string{"172.17.1.1"},
			mockNetInfo,
			scanner.WithPacketCapture(capture),
			scanner.WithRequestNotifications(requestNotifier),
		)

		mockNetInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		mockNetInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		mockNetInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

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
