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

// Option represents an option that can be passed to any of the
// "New" scanner constructors
type Option = func(s Scanner)

// WithRequestNotifications sets channel for request notifications
func WithRequestNotifications(c chan *Request) Option {
	return func(s Scanner) {
		s.SetRequestNotifications(c)
	}
}

// WithIdleTimeout sets the idle timeout for the scanner
func WithIdleTimeout(duration time.Duration) Option {
	return func(s Scanner) {
		s.SetIdleTimeout(duration)
	}
}

// WithVendorInfo sets whether or not to include vendor info when scanning
func WithVendorInfo(repo oui.VendorRepo) Option {
	return func(s Scanner) {
		s.IncludeVendorInfo(repo)
	}
}

// WithHostnames sets whether or not to perform reverse dns lookup
func WithHostnames(v bool) Option {
	return func(s Scanner) {
		s.IncludeHostNames(v)
	}
}

// WithPacketCapture sets the packet capture implementation for the scanner
func WithPacketCapture(cap PacketCapture) Option {
	return func(s Scanner) {
		s.SetPacketCapture(cap)
	}
}

// WithTiming sets the timing duration for how long to wait in-between each
// packet send
func WithTiming(duration time.Duration) Option {
	return func(s Scanner) {
		s.SetTiming(duration)
	}
}
