// SPDX-License-Identifier: GPL-3.0-or-later

package logger_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	defer func() {
		logger.SetGlobalLevel(zerolog.DebugLevel)
		logger.Reset()
	}()

	t.Run("sets global log level", func(st *testing.T) {
		defer func() {
			logger.SetGlobalLevel(zerolog.DebugLevel)
			logger.Reset()
		}()

		b := []byte{}
		buf := bytes.NewBuffer(b)

		logger.SetBufferOutput(buf)
		logger.SetGlobalLevel(zerolog.ErrorLevel)

		log := logger.New()

		testString := "this is a test string"

		log.Debug().Msg(testString)
		assert.NotContains(st, buf.String(), testString)

		log.Info().Msg(testString)
		assert.NotContains(st, buf.String(), testString)

		log.Warn().Msg(testString)
		assert.NotContains(st, buf.String(), testString)

		log.Error().Msg(testString)
		assert.Contains(st, buf.String(), testString)
	})

	t.Run("sets caller option", func(st *testing.T) {
		defer func() {
			logger.SetGlobalLevel(zerolog.DebugLevel)
			logger.Reset()
		}()

		b := []byte{}
		buf := bytes.NewBuffer(b)

		logger.SetBufferOutput(buf)
		logger.SetGlobalLevel(zerolog.DebugLevel)
		logger.SetWithCaller()

		log := logger.New()

		testString := "this is a test string"

		log.Info().Msg(testString)
		output := buf.String()
		assert.Contains(st, output, testString)
		assert.Contains(st, output, "logger_test.go")
	})

	t.Run("sets timestamp option", func(st *testing.T) {
		defer func() {
			logger.SetGlobalLevel(zerolog.DebugLevel)
			logger.Reset()
		}()

		b := []byte{}
		buf := bytes.NewBuffer(b)

		logger.SetBufferOutput(buf)
		logger.SetGlobalLevel(zerolog.DebugLevel)
		logger.SetWithTimestamp()

		log := logger.New()

		testString := "this is a test string"

		log.Info().Msg(testString)
		output := buf.String()
		assert.Contains(st, output, testString)
		assert.Contains(st, output, "\"time\":")
	})

	t.Run("sets global log file option", func(st *testing.T) {
		outFileName := "logger_test_out.txt"

		writeFile, err := os.Create(outFileName)

		assert.NoError(st, err)

		defer func() {
			writeFile.Close()
			os.RemoveAll(writeFile.Name())
			logger.SetGlobalLevel(zerolog.DebugLevel)
			logger.Reset()
		}()

		logger.SetGlobalLevel(zerolog.DebugLevel)
		logger.SetGlobalLogFile(writeFile)

		log := logger.New()

		testString := "this is a test string"

		log.Info().Msg(testString)

		readFile, err := os.Open(outFileName)

		assert.NoError(st, err)

		defer readFile.Close()

		output, err := io.ReadAll(readFile)

		assert.NoError(st, err)
		assert.Contains(st, string(output), testString)
	})
}
