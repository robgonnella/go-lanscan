package vendor_test

import (
	"net"
	"os"
	"path"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/vendor"
	"github.com/stretchr/testify/assert"
)

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

		err = vendor.UpdateStaticVendors(ouiTxt)

		assert.NoError(st, err)

		info, err := os.Stat(ouiTxt)

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, info.Name())
	})
}

func TestQueryVendor(t *testing.T) {
	t.Run("queries and finds vendor", func(st *testing.T) {
		hw, err := net.ParseMAC("00-00-0C-CC-CC-CC")

		assert.NoError(t, err)

		repo, err := vendor.GetDefaultVendorRepo()

		assert.NoError(st, err)

		v, err := repo.Query(hw)

		assert.NoError(st, err)

		assert.Equal(st, v.Name, "Cisco Systems, Inc")
	})

	t.Run("returns error", func(st *testing.T) {
		hw, err := net.ParseMAC("ff-ff-ff-ff-ff-ff")

		assert.NoError(t, err)

		repo, err := vendor.GetDefaultVendorRepo()

		assert.NoError(st, err)

		v, err := repo.Query(hw)

		assert.Error(st, err)

		assert.Nil(st, v)
	})
}
