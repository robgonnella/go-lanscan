// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"time"

	"github.com/robgonnella/go-lanscan/pkg/oui"
)

type ScannerOption = func(s Scanner)

type Accuracy int

const (
	LOW_ACCURACY    Accuracy = 0
	MEDIUM_ACCURACY Accuracy = 1
	HIGH_ACCURACY   Accuracy = 2
)

func (a Accuracy) Duration() time.Duration {
	switch a {
	case LOW_ACCURACY:
		return time.Microsecond * 100
	case MEDIUM_ACCURACY:
		return time.Microsecond * 500
	case HIGH_ACCURACY:
		return time.Millisecond
	default:
		return time.Millisecond
	}
}

func WithAccuracy(accuracy Accuracy) ScannerOption {
	return func(s Scanner) {
		s.SetAccuracy(accuracy)
	}
}

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
