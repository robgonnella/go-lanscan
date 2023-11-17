// SPDX-License-Identifier: GPL-3.0-or-later

package cli_test

import (
	"net"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/cli"
	mock_core "github.com/robgonnella/go-lanscan/internal/mock/core"
	mock_network "github.com/robgonnella/go-lanscan/mock/network"
	mock_oui "github.com/robgonnella/go-lanscan/mock/oui"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestUpdatesVendorsCommand(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	t.Run("updates static vendor file", func(st *testing.T) {
		mockNetwork := mock_network.NewMockNetwork(ctrl)

		mockRunner := mock_core.NewMockRunner(ctrl)

		mockVendor := mock_oui.NewMockVendorRepo(ctrl)

		mockMAC, _ := net.ParseMAC("00:00:00:00:00:00")

		mockCidr := "172.17.1.1/32"

		mockNetwork.EXPECT().Interface().AnyTimes().Return(&net.Interface{
			Name:         "test-interface",
			HardwareAddr: mockMAC,
		})

		mockNetwork.EXPECT().Cidr().AnyTimes().Return(mockCidr)

		mockVendor.EXPECT().UpdateVendors()

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"update-vendors"})

		err = cmd.Execute()

		assert.NoError(st, err)
	})
}
