package scanner_test

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/google/gopacket"
	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
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

	mockUserIP := net.ParseIP("172.17.1.1")

	t.Run("returns immediately if already scanning", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

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
			resultChan,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}

		wg.Add(1)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				synScanner.Stop()
				wg.Done()
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
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

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
			resultChan,
			scanner.WithPacketCapture(cap),
		)

		mockErr := errors.New("mock open-live error")

		wg := sync.WaitGroup{}

		wg.Add(1)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(nil, mockErr)

		err := synScanner.Scan()

		assert.Error(st, err)
		assert.ErrorIs(st, mockErr, err)
	})

	t.Run("performs syn scan ", func(st *testing.T) {
		cap := mock_scanner.NewMockPacketCapture(ctrl)
		handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)
		netInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

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
			resultChan,
			scanner.WithPacketCapture(cap),
		)

		wg := sync.WaitGroup{}

		wg.Add(1)

		netInfo.EXPECT().Interface().AnyTimes().Return(mockInterface)
		netInfo.EXPECT().UserIP().Return(mockUserIP)

		cap.EXPECT().OpenLive(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			gomock.Any()).Return(handle, nil)

		cap.EXPECT().SerializeLayers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		handle.EXPECT().SetBPFFilter(gomock.Any())
		handle.EXPECT().Close().AnyTimes()

		handle.EXPECT().WritePacketData(gomock.Any()).DoAndReturn(func(data []byte) (err error) {
			defer func() {
				synScanner.Stop()
				wg.Done()
			}()
			return nil
		})

		handle.EXPECT().ReadPacketData().AnyTimes().DoAndReturn(func() (data []byte, ci gopacket.CaptureInfo, err error) {
			return []byte{}, gopacket.CaptureInfo{}, nil
		})

		err := synScanner.Scan()

		assert.NoError(st, err)
	})
}
