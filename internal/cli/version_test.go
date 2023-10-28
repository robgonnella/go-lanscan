// SPDX-License-Identifier: GPL-3.0-or-later

package cli_test

import (
	"bytes"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/cli"
	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/info"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/stretchr/testify/assert"
)

func TestVersionCommand(t *testing.T) {
	b := []byte{}
	buf := bytes.NewBuffer(b)

	logger.SetBufferOutput(buf)

	t.Run("prints versions to console", func(st *testing.T) {
		runner := core.New()

		cmd, err := cli.Root(runner)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"version"})
		err = cmd.Execute()

		assert.NoError(st, err)

		output := buf.String()

		assert.Contains(st, output, info.VERSION)
	})
}
