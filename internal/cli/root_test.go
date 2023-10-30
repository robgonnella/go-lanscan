package cli_test

import (
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/cli"
	mock_core "github.com/robgonnella/go-lanscan/internal/mock/core"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRootCommand(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("initializes runner and performs scan", func(st *testing.T) {
		mockRunner := mock_core.NewMockRunner(ctrl)

		netInfo, err := network.GetNetworkInfo()

		assert.NoError(st, err)

		ouiTxt, err := util.GetDefaultOuiTxtPath()

		assert.NoError(st, err)

		os.RemoveAll(*ouiTxt)

		cmd, err := cli.Root(mockRunner)

		assert.NoError(st, err)

		mockRunner.EXPECT().Initialize(
			"high",
			[]string{},
			netInfo,
			[]string{"1-65535"},
			uint16(54321),
			5,
			false,
			false,
			false,
			false,
		)

		mockRunner.EXPECT().Run()

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
