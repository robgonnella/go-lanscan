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
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestArpScanner(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockInterface := &net.Interface{
		Name:         "interfaceName",
		HardwareAddr: net.HardwareAddr{},
	}

	_, mockIPNet, _ := net.ParseCIDR("172.17.1.1/32")

	mockUserIP := net.ParseIP("172.17.1.1")

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
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet)
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
			return []byte{}, gopacket.CaptureInfo{}, nil
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
		mockNetInfo.EXPECT().IPNet().Return(mockIPNet)
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
			return []byte{}, gopacket.CaptureInfo{}, nil
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
			return []byte{}, gopacket.CaptureInfo{}, nil
		})

		err := arpScanner.Scan()

		wg.Wait()

		assert.NoError(st, err)
	})

	// t.Run("handles arp reply", func(st *testing.T) {
	// 	cap := mock_scanner.NewMockPacketCapture(ctrl)
	// 	handle := mock_scanner.NewMockPacketCaptureHandle(ctrl)

	// 	resultChan := make(chan *scanner.ScanResult)

	// 	arpScanner := scanner.NewArpScanner(
	// 		[]string{"172.17.1.1"},
	// 		netInfo,
	// 		resultChan,
	// 		ouiTxt,
	// 		scanner.WithPacketCapture(cap),
	// 	)

	// 	cap.EXPECT().OpenLive(
	// 		gomock.Any(),
	// 		gomock.Any(),
	// 		gomock.Any(),
	// 		gomock.Any()).Return(handle, nil)

	// 	handle.EXPECT().Close().AnyTimes()
	// 	handle.EXPECT().ReadPacketData().AnyTimes()
	// 	handle.EXPECT().WritePacketData(gomock.Any()).AnyTimes()

	// })

}
