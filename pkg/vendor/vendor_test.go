package vendor_test

import (
	"net"
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/vendor"
	"github.com/stretchr/testify/assert"
)

func TestUpdateVendors(t *testing.T) {
	ouiTxt := "oui.txt"

	reset := func() error {
		return os.RemoveAll(ouiTxt)
	}

	t.Run("updates static vendor file", func(st *testing.T) {
		reset()
		defer reset()

		_, err := os.Stat(ouiTxt)

		assert.True(st, os.IsNotExist(err))

		repo, err := vendor.NewOUIVendorRepo(ouiTxt)

		assert.NoError(st, err)

		err = repo.UpdateVendors()

		assert.NoError(st, err)

		info, err := os.Stat(ouiTxt)

		assert.NoError(st, err)

		assert.Equal(st, ouiTxt, info.Name())
	})
}

func TestQueryVendor(t *testing.T) {
	ouiTxt := "oui2.txt"

	reset := func() error {
		return os.RemoveAll(ouiTxt)
	}

	reset()
	defer reset()

	repo, err := vendor.NewOUIVendorRepo(ouiTxt)

	assert.NoError(t, err)

	t.Run("queries and finds vendor", func(st *testing.T) {
		hw, err := net.ParseMAC("00-00-0C-CC-CC-CC")

		assert.NoError(t, err)

		v, err := repo.Query(hw)

		assert.NoError(st, err)

		assert.Equal(st, v.Name, "Cisco Systems, Inc")
	})

	t.Run("returns error", func(st *testing.T) {
		hw, err := net.ParseMAC("ff-ff-ff-ff-ff-ff")

		assert.NoError(t, err)

		v, err := repo.Query(hw)

		assert.Error(st, err)

		assert.Nil(st, v)
	})
}
