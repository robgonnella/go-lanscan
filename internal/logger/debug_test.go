package logger_test

import (
	"testing"

	"github.com/robgonnella/go-lanscan/internal/logger"
)

func TestDebugLogging(t *testing.T) {
	debug := logger.NewDebugLogger()

	t.Run("prints nothing since not built with debug flag", func(st *testing.T) {
		debug.Debug().Msg("debug message")
		debug.Info().Msg("info message")
		debug.Error().Msg("error message")
		debug.Warn().Msg("warning message")
	})
}
