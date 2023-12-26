// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"time"

	"github.com/robgonnella/go-lanscan/pkg/oui"
)

// How long to wait before sending next packet
// the faster you send packets the more packets
// will be missed when reading
const defaultTiming = time.Microsecond * 100

// If no packets are received for this period of time, exit with timeout
const defaultIdleTimeout = time.Second * 5

type ScannerOption = func(s Scanner)

func WithRequestNotifications(c chan *Request) ScannerOption {
	return func(s Scanner) {
		s.SetRequestNotifications(c)
	}
}

func WithIdleTimeout(duration time.Duration) ScannerOption {
	return func(s Scanner) {
		s.SetIdleTimeout(duration)
	}
}

func WithVendorInfo(repo oui.VendorRepo) ScannerOption {
	return func(s Scanner) {
		s.IncludeVendorInfo(repo)
	}
}

func WithPacketCapture(cap PacketCapture) ScannerOption {
	return func(s Scanner) {
		s.SetPacketCapture(cap)
	}
}

func WithTiming(duration time.Duration) ScannerOption {
	return func(s Scanner) {
		s.SetTiming(duration)
	}
}
