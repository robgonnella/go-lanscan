// SPDX-License-Identifier: GPL-3.0-or-later

package vendor_test

import (
	"os"
	"path"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/vendor"
	"github.com/stretchr/testify/assert"
)

func TestGetDefaultVendorRepo(t *testing.T) {
	t.Run("gets default vendor repo", func(st *testing.T) {
		repo, err := vendor.GetDefaultVendorRepo()

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
		filePath, err := vendor.GetDefaultOuiTxtPath()

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, *filePath)
	})
}
