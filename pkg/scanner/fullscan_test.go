// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
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

func TestFullScanner(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockInterface := &net.Interface{
		Name:         "interfaceName",
		HardwareAddr: net.HardwareAddr([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
	}

	cidr := "172.17.1.1/32"
	_, mockIPNet, _ := net.ParseCIDR(cidr)

	mockUserIP := net.ParseIP("172.17.1.1")

	t.Run("returns immediately if already scanning", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		fullScanner := scanner.NewFullScanner(
			netInfo,
			[]string{},
			[]string{},
			54321,
			scanner.WithPacketCapture(capture),
		)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().IPNet().Return(mockIPNet)
		netInfo.EXPECT().UserIP().Return(mockUserIP)
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any()).AnyTimes()
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				time.AfterFunc(time.Millisecond*500, fullScanner.Stop)
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return []byte{}, gopacket.CaptureInfo{}, nil
		})

		go fullScanner.Scan()

		err := fullScanner.Scan()

		assert.NoError(st, err)
	})

	t.Run("performs full scan on default network for all ports", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		sentArpResult := false

		fullScanner := scanner.NewFullScanner(
			netInfo,
			[]string{},
			[]string{},
			54321,
			scanner.WithPacketCapture(capture),
		)

		resultChan := fullScanner.Results()

		wg := sync.WaitGroup{}

		wg.Add(1)

		netInfo.EXPECT().Interface().Return(mockInterface).AnyTimes()
		netInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		netInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any()).AnyTimes()
		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		}).AnyTimes()

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !sentArpResult {
				sentArpResult = true
				return test_helper.NewArpReplyReadResult(
					mockUserIP,
					[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				)
			}

			return test_helper.NewSynWithAckResponsePacketBytes(
				mockUserIP,
				3000,
				54321,
			)
		})

		go func() {
			for res := range resultChan {
				if res.Type == scanner.SYNDone {
					wg.Done()
				}
			}
		}()

		err := fullScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	t.Run("performs full scan on provided targets and ports", func(st *testing.T) {
		capture := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		sentArpResult := false

		fullScanner := scanner.NewFullScanner(
			netInfo,
			[]string{"172.17.1.1"},
			[]string{"22"},
			54321,
			scanner.WithPacketCapture(capture),
		)

		resultChan := fullScanner.Results()

		wg := sync.WaitGroup{}

		wg.Add(1)

		netInfo.EXPECT().Interface().Return(mockInterface).AnyTimes()
		netInfo.EXPECT().UserIP().Return(mockUserIP).AnyTimes()
		netInfo.EXPECT().IPNet().Return(mockIPNet).AnyTimes()
		netInfo.EXPECT().Cidr().AnyTimes().Return(cidr)

		capture.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any()).AnyTimes()
		capture.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			return nil
		}).AnyTimes()

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			if !sentArpResult {
				sentArpResult = true
				return test_helper.NewArpReplyReadResult(
					mockUserIP,
					[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				)
			}

			return test_helper.NewSynWithAckResponsePacketBytes(
				mockUserIP,
				3000,
				54321,
			)
		})

		go func() {
			for res := range resultChan {
				if res.Type == scanner.SYNDone {
					wg.Done()
				}
			}
		}()

		err := fullScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

}
