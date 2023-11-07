// SPDX-License-Identifier: GPL-3.0-or-later

package cli_test

import (
	"testing"

	"github.com/robgonnella/go-lanscan/internal/cli"
	mock_core "github.com/robgonnella/go-lanscan/internal/mock/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRootCommand(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("initializes high accuracy and runs", func(st *testing.T) {
		mockRunner := mock_core.NewMockRunner(ctrl)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			1,
			false,
			false,
			false,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"--ports", "22", "--accuracy", "high"})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("initializes medium accuracy and runs", func(st *testing.T) {
		mockRunner := mock_core.NewMockRunner(ctrl)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			1,
			1,
			true,
			true,
			true,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner)

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
		mockRunner := mock_core.NewMockRunner(ctrl)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
			1,
			false,
			false,
			false,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner)

		assert.NoError(st, err)

		cmd.SetArgs([]string{
			"--ports", "22",
			"--accuracy", "low",
		})

		err = cmd.Execute()

		assert.NoError(st, err)
	})

	t.Run("initializes unknown accuracy and runs", func(st *testing.T) {
		mockRunner := mock_core.NewMockRunner(ctrl)

		mockRunner.EXPECT().Initialize(
			gomock.Any(),
			gomock.Any(),
			1,
			1,
			true,
			true,
			true,
		)

		mockRunner.EXPECT().Run().Return(nil)

		cmd, err := cli.Root(mockRunner)

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
		mockRunner := mock_core.NewMockRunner(ctrl)

		cmd, err := cli.Root(mockRunner)

		assert.NoError(st, err)

		cmd.SetArgs([]string{"--interface", "nope"})

		err = cmd.Execute()

		assert.Error(st, err)
	})
}
