// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
	"testing"
	"time"

	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_oui "github.com/robgonnella/go-lanscan/mock/oui"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"go.uber.org/mock/gomock"
)

func TestOptions(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	testPacketCapture := mock_scanner.NewMockPacketCapture(ctrl)
	vendorRepo := mock_oui.NewMockVendorRepo(ctrl)

	vendorRepo.EXPECT().UpdateVendors().Times(2)

	t.Run("sets options", func(st *testing.T) {
		netInfo := mock_network.NewMockNetwork(ctrl)
		requestNotifier := make(chan *scanner.Request)

		scanner.NewArpScanner(
			[]string{},
			netInfo,
			scanner.WithTiming(time.Millisecond),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(requestNotifier),
			scanner.WithVendorInfo(vendorRepo),
			scanner.WithHostnames(true),
		)

		scanner.NewFullScanner(
			netInfo,
			[]string{},
			[]string{},
			54321,
			scanner.WithTiming(time.Millisecond),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(requestNotifier),
			scanner.WithVendorInfo(vendorRepo),
			scanner.WithHostnames(true),
		)

		scanner.NewSynScanner(
			[]*scanner.ArpScanResult{},
			netInfo,
			[]string{},
			54321,
			scanner.WithTiming(time.Millisecond),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(requestNotifier),
			scanner.WithVendorInfo(vendorRepo),
			scanner.WithHostnames(true),
		)
	})
}
