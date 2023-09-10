// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import "time"

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

func WithVendorInfo(value bool) ScannerOption {
	return func(s Scanner) {
		scanner, ok := s.(*ArpScanner)

		if !ok {
			return
		}

		scanner.includeVendor = value
	}
}
