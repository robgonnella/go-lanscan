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

func TestRootCommand(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("initializes high accuracy and runs", func(st *testing.T) {
		mockNetwork := mock_network.NewMockNetwork(ctrl)

		mockRunner := mock_core.NewMockRunner(ctrl)

		mockVendor := mock_oui.NewMockVendorRepo(ctrl)

		mockMAC, _ := net.ParseMAC("00:00:00:00:00:00")

		mockCidr := "172.17.1.1/32"

		_, mockIPNet, _ := net.ParseCIDR(mockCidr)

		mockNetwork.EXPECT().Interface().AnyTimes().Return(&net.Interface{
			Name:         "test-interface",
			HardwareAddr: mockMAC,
		})

		mockNetwork.EXPECT().Cidr().AnyTimes().Return(mockCidr)

		mockNetwork.EXPECT().IPNet().AnyTimes().Return(mockIPNet)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			1,
			false,
			false,
			false,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"--ports", "22", "--accuracy", "high"})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("initializes medium accuracy and runs", func(st *testing.T) {
		mockNetwork := mock_network.NewMockNetwork(ctrl)

		mockRunner := mock_core.NewMockRunner(ctrl)

		mockVendor := mock_oui.NewMockVendorRepo(ctrl)

		mockMAC, _ := net.ParseMAC("00:00:00:00:00:00")

		mockCidr := "172.17.1.1/32"

		_, mockIPNet, _ := net.ParseCIDR(mockCidr)

		mockNetwork.EXPECT().Interface().AnyTimes().Return(&net.Interface{
			Name:         "test-interface",
			HardwareAddr: mockMAC,
		})

		mockNetwork.EXPECT().Cidr().AnyTimes().Return(mockCidr)

		mockNetwork.EXPECT().IPNet().AnyTimes().Return(mockIPNet)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			1,
			1,
			true,
			true,
			true,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{
			"--targets",
			"172.17.1.1",
			"--ports", "22",
			"--accuracy", "medium",
			"--arp-only",
			"--json",
			"--no-progress",
		})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("initializes low accuracy and runs", func(st *testing.T) {
		mockNetwork := mock_network.NewMockNetwork(ctrl)

		mockRunner := mock_core.NewMockRunner(ctrl)

		mockVendor := mock_oui.NewMockVendorRepo(ctrl)

		mockMAC, _ := net.ParseMAC("00:00:00:00:00:00")

		mockCidr := "172.17.1.1/32"

		_, mockIPNet, _ := net.ParseCIDR(mockCidr)

		mockNetwork.EXPECT().Interface().AnyTimes().Return(&net.Interface{
			Name:         "test-interface",
			HardwareAddr: mockMAC,
		})

		mockNetwork.EXPECT().Cidr().AnyTimes().Return(mockCidr)

		mockNetwork.EXPECT().IPNet().AnyTimes().Return(mockIPNet)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			1,
			false,
			false,
			false,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{
			"--ports", "22",
			"--accuracy", "low",
		})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("initializes unknown accuracy and runs", func(st *testing.T) {
		mockNetwork := mock_network.NewMockNetwork(ctrl)

		mockRunner := mock_core.NewMockRunner(ctrl)

		mockVendor := mock_oui.NewMockVendorRepo(ctrl)

		mockMAC, _ := net.ParseMAC("00:00:00:00:00:00")

		mockCidr := "172.17.1.1/32"

		_, mockIPNet, _ := net.ParseCIDR(mockCidr)

		mockNetwork.EXPECT().Interface().AnyTimes().Return(&net.Interface{
			Name:         "test-interface",
			HardwareAddr: mockMAC,
		})

		mockNetwork.EXPECT().Cidr().AnyTimes().Return(mockCidr)

		mockNetwork.EXPECT().IPNet().AnyTimes().Return(mockIPNet)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			1,
			1,
			true,
			true,
			true,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{
			"--targets", "172.17.1.1",
			"--ports", "22",
			"--accuracy", "unknown",
			"--arp-only",
			"--json",
			"--no-progress",
		})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("gets provided fake interface and returns error", func(st *testing.T) {
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

		cmd, err := cli.Root(mockRunner, mockNetwork, mockVendor)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"--interface", "nope"})

		err = cmd.Execute()

		assert.Error(st, err)
	})
}
