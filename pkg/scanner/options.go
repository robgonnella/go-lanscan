// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"time"

	"github.com/robgonnella/go-lanscan/pkg/oui"
)

// How long to wait before sending next packet
// the faster you send packets the more packets
// will be missed when reading
const defaultAccuracy = time.Millisecond * 100

type ScannerOption = func(s Scanner)

func WithRequestNotifications(cb func(a *Request)) ScannerOption {
	return func(s Scanner) {
		s.SetRequestNotifications(cb)
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
