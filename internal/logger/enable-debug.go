// SPDX-License-Identifier: GPL-3.0-or-later

//go:build debug

package logger

import (
	"os"

	"github.com/rs/zerolog"
)

func init() {
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr}

	zl := zerolog.New(consoleWriter).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	*debugLogger.zl = zl
}
