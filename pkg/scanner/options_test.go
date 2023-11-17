// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
	"testing"
	"time"

	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	mock_vendor "github.com/robgonnella/go-lanscan/mock/vendor"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAccuracy(t *testing.T) {
	t.Run("returns duration for accuracy type", func(st *testing.T) {
		unknownAccuracy := scanner.Accuracy(3)

		assert.Equal(st, time.Microsecond*100, scanner.LOW_ACCURACY.Duration())
		assert.Equal(st, time.Microsecond*500, scanner.MEDIUM_ACCURACY.Duration())
		assert.Equal(st, time.Millisecond, scanner.HIGH_ACCURACY.Duration())
		assert.Equal(st, time.Millisecond, unknownAccuracy.Duration())
	})
}

func TestOptions(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	testPacketCapture := mock_scanner.NewMockPacketCapture(ctrl)
	vendorRepo := mock_vendor.NewMockVendorRepo(ctrl)

	t.Run("sets options", func(st *testing.T) {
		netInfo := mock_network.NewMockNetwork(ctrl)

		resultChan := make(chan *scanner.ScanResult)

		scanner.NewArpScanner(
			[]string{},
			netInfo,
			resultChan,
			vendorRepo,
			scanner.WithAccuracy(scanner.HIGH_ACCURACY),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(func(r *scanner.Request) {}),
			scanner.WithVendorInfo(true),
		)

		scanner.NewFullScanner(
			netInfo,
			[]string{},
			[]string{},
			54321,
			resultChan,
			vendorRepo,
			scanner.WithAccuracy(scanner.HIGH_ACCURACY),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(func(r *scanner.Request) {}),
			scanner.WithVendorInfo(true),
		)

		scanner.NewSynScanner(
			[]*scanner.ArpScanResult{},
			netInfo,
			[]string{},
			54321,
			resultChan,
			scanner.WithAccuracy(scanner.HIGH_ACCURACY),
			scanner.WithIdleTimeout(time.Second*5),
			scanner.WithPacketCapture(testPacketCapture),
			scanner.WithRequestNotifications(func(r *scanner.Request) {}),
			scanner.WithVendorInfo(true),
		)
	})
}
