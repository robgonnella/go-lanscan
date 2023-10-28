// SPDX-License-Identifier: GPL-3.0-or-later

package logger

import (
	"bytes"
	"os"

	"github.com/rs/zerolog"
)

// Logger our internal "singleton" wrapper around zerolog allowing us
// to set all loggers to log to file or console all at once
type Logger struct {
	zl *zerolog.Logger
}

// unexported "singleton" logger
var logger Logger

// init sets the internal "singleton" logger
func init() {
	Reset()
}

// New returns the internal "singleton" logger
func New() Logger {
	return logger
}

// SetGlobalLevel set level for all loggers
func SetGlobalLevel(level zerolog.Level) {
	if level == zerolog.DebugLevel {
		SetWithCaller()
		SetWithTimestamp()
	}

	zerolog.SetGlobalLevel(level)
}

// SetWithCaller enables showing caller in log context
func SetWithCaller() {
	newZl := logger.zl.With().Caller().Logger()
	*logger.zl = newZl
}

// SetWithTimestamp enables showing timestamp in log context
func SetWithTimestamp() {
	newZl := logger.zl.With().Timestamp().Logger()
	*logger.zl = newZl
}

// SetGlobalLogFile set all loggers to log to file
func SetGlobalLogFile(f *os.File) {
	newZl := logger.zl.Output(f)

	*logger.zl = newZl
}

// SetBufferOutput sets logger output (only used for testing)
func SetBufferOutput(buf *bytes.Buffer) {
	newZl := logger.zl.Output(buf)

	*logger.zl = newZl
}

// Reset resets logger to default values
func Reset() {
	zl := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Logger()

	logger = Logger{
		zl: &zl,
	}
}

// Info wrapper around zerolog Info
func (l Logger) Info() *zerolog.Event {
	return l.zl.Info()
}

// Debug wrapper around zerolog Debug
func (l Logger) Debug() *zerolog.Event {
	return l.zl.Debug()
}

// Warn wrapper around zerolog Warn
func (l Logger) Warn() *zerolog.Event {
	return l.zl.Warn()
}

// Error wrapper around zerolog Error
func (l Logger) Error() *zerolog.Event {
	return l.zl.Error()
}

// Fatal wrapper around zerolog Fatal
func (l Logger) Fatal() *zerolog.Event {
	return l.zl.Fatal()
}
