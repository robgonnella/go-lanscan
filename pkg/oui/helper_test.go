// SPDX-License-Identifier: GPL-3.0-or-later

package oui_test

import (
	"os"
	"path"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/oui"
	"github.com/stretchr/testify/assert"
)

func TestGetDefaultVendorRepo(t *testing.T) {
	t.Run("gets default vendor repo", func(st *testing.T) {
		repo, err := oui.GetDefaultVendorRepo()

		assert.NotNil(st, repo)
		assert.NoError(st, err)
	})
}

func TestGetDefaultOuiTxtPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()

	assert.NoError(t, err)

	confDir := path.Join(homeDir, ".config", "go-lanscan")

	ouiTxt := path.Join(confDir, "oui.txt")

	t.Run("returns default oui.txt path", func(st *testing.T) {
		filePath, err := oui.GetDefaultOuiTxtPath()

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, *filePath)
	})
}
