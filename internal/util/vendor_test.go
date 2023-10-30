package util_test

import (
	"os"
	"path"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestGetDefaultOuiTxtPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()

	assert.NoError(t, err)

	confDir := path.Join(homeDir, ".config", "go-lanscan")

	ouiTxt := path.Join(confDir, "oui.txt")

	t.Run("returns default oui.txt path", func(st *testing.T) {
		filePath, err := util.GetDefaultOuiTxtPath()

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, *filePath)
	})
}

func TestUpdateStaticVendors(t *testing.T) {
	ouiTxt := "oui.txt"

	reset := func() error {
		return os.RemoveAll(ouiTxt)
	}

	t.Run("updates static vendor file", func(st *testing.T) {
		reset()
		defer reset()

		_, err := os.Stat(ouiTxt)
		assert.True(st, os.IsNotExist(err))

		err = util.UpdateStaticVendors(ouiTxt)

		assert.NoError(st, err)

		info, err := os.Stat(ouiTxt)

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, info.Name())
	})
}
