package scanner

import "time"

type ScannerOption = func(s Scanner)

func WithRequestNotifications(cb func(a *Request)) ScannerOption {
	return func(s Scanner) {
		s.SetRequestNotifications(cb)
	}
}

func WithSynIdleTimeout(duration time.Duration) ScannerOption {
	return func(s Scanner) {
		s.SetIdleTimeout(duration)
	}
}
