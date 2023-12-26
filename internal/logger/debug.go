// SPDX-License-Identifier: GPL-3.0-or-later

package logger

import (
	"io"

	"github.com/rs/zerolog"
)

var debugLogger DebugLogger

func init() {
	// initialize a disabled logger
	// builds with the "debug" tag will enable logging
	// see enable-debug.go

	consoleWriter := zerolog.ConsoleWriter{Out: io.Discard}

	zl := zerolog.New(consoleWriter).
		Level(zerolog.Disabled).
		With().
		Timestamp().
		Caller().
		Logger()

	debugLogger = DebugLogger{
		zl: &zl,
	}
}

// DebugLogger represents a Logger implementation that is only turned on
// when build with the "debug" tag
type DebugLogger struct {
	zl *zerolog.Logger
}

// NewDebugLogger returns a instance of DebugLogger
func NewDebugLogger() DebugLogger {
	return debugLogger
}

// Info wrapper around zerolog Info
func (l DebugLogger) Info() *zerolog.Event {
	return l.zl.Info()
}

// Debug wrapper around zerolog Debug
func (l DebugLogger) Debug() *zerolog.Event {
	return l.zl.Debug()
}

// Warn wrapper around zerolog Warn
func (l DebugLogger) Warn() *zerolog.Event {
	return l.zl.Warn()
}

// Error wrapper around zerolog Error
func (l DebugLogger) Error() *zerolog.Event {
	return l.zl.Error()
}

// Fatal wrapper around zerolog Fatal
func (l DebugLogger) Fatal() *zerolog.Event {
	return l.zl.Fatal()
}
