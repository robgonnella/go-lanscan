// SPDX-License-Identifier: GPL-3.0-or-later

package cli_test

import (
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/cli"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestUpdatesVendorsCommand(t *testing.T) {
	t.Run("updates static vendor file", func(st *testing.T) {
		ouiTxt, err := util.GetDefaultOuiTxtPath()

		assert.NoError(st, err)

		err = os.RemoveAll(*ouiTxt)

		assert.NoError(st, err)

		cmd, err := cli.NewRoot()

		assert.NoError(st, err)

		cmd.SetArgs([]string{"update-vendors"})
		err = cmd.Execute()

		assert.NoError(st, err)

		info, err := os.Stat(*ouiTxt)

		assert.NoError(st, err)

		assert.False(st, info.IsDir())
	})
}
