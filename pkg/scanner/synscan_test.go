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
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	test_helper "github.com/robgonnella/go-lanscan/pkg/internal/test-helper"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSynScanner(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockInterface := &net.Interface{
		Name:         "interfaceName",
		HardwareAddr: net.HardwareAddr{},
	}

	cidr := "172.17.1.1/32"

	mockUserIP := net.ParseIP("172.17.1.1")

	t.Run("returns immediately if already scanning", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				time.AfterFunc(time.Millisecond*500, synScanner.Stop)
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return []byte{}, gopacket.CaptureInfo{}, nil
		})

		go synScanner.Scan()

		err := synScanner.Scan()

		assert.NoError(st, err)
	})

	t.Run("returns error if PacketCapture.OpenLive return error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		mockErr := errors.New("mock open-live error")

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(nil, mockErr)

		err := synScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("prints debug message if reading packets returns error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		wg := sync.WaitGroup{}
		wg.Add(1)

		listenPort := uint16(54321)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			listenPort,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
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
					synScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				22,
				listenPort,
			)
		})

		err := synScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("returns error if SetBPFFilter returns error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		mockErr := errors.New("mock SetBPFFilter error")

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		handle.EXPECT().SetBPFFilter(gomock.Any()).Return(mockErr)

		err := synScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("returns error if WritePacketData returns error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		mockErr := errors.New("mock WritePacketData error")

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		handle.EXPECT().SetBPFFilter(gomock.Any())
		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return mockErr
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				3000,
				54321,
			)
		})

		err := synScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("returns error if SerializeLayers returns error", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		mockErr := errors.New("mock SerializeLayers error")

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		handle.EXPECT().SetBPFFilter(gomock.Any())

		capture.EXPECT().SerializeLayers(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
		).
			AnyTimes().
			Return(mockErr)

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				3000,
				54321,
			)
		})

		err := synScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("performs syn scan ", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		wg := sync.WaitGroup{}
		wg.Add(1)

		listenPort := uint16(54321)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			listenPort,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					synScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				22,
				listenPort,
			)
		})

		err := synScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("ignores packet from unexpected target ", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		wg := sync.WaitGroup{}
		wg.Add(1)

		listenPort := uint16(54321)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			listenPort,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					synScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("192.168.22.1"),
				3000,
				listenPort,
			)
		})

		err := synScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("ignores packet that have wrong destination port", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)
		packetSent := false

		wg := sync.WaitGroup{}
		wg.Add(1)

		listenPort := uint16(54321)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			listenPort,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					synScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				3000,
				54322,
			)
		})

		err := synScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("sends request notifications", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)
		requestNotifier := make(chan *scanner.Request)
		packetSent := false
		notified := false

		wg := sync.WaitGroup{}
		wg.Add(2)

		go func() {
			<-requestNotifier
			notified = true
			wg.Done()
		}()

		listenPort := uint16(54321)

		synScanner := scanner.NewSynScanner(
			[]*scanner.ArpScanResult{
				{
					IP:     net.ParseIP("172.17.1.1"),
					MAC:    mockInterface.HardwareAddr,
					Vendor: "unknown",
				},
			},
			netInfo,
			[]string{"22"},
			listenPort,
			scanner.WithPacketCapture(capture),
			scanner.WithRequestNotifications(requestNotifier),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !packetSent {
				packetSent = true
				defer func() {
					synScanner.Stop()
					wg.Done()
				}()
			}
			return test_helper.NewSynWithAckResponsePacketBytes(
				net.ParseIP("172.17.1.1"),
				3000,
				54322,
			)
		})

		err := synScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)

		assert.True(st, notified)
	})
}
