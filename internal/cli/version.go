// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"github.com/robgonnella/go-lanscan/internal/info"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/spf13/cobra"
)

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Prints version",
		Run: func(cmd *cobra.Command, args []string) {
			logger.New().Info().Msgf("go-lanscan: %s", info.VERSION)
		},
	}
}
