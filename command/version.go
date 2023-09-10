// SPDX-License-Identifier: GPL-3.0-or-later

package command

import (
	"github.com/robgonnella/go-lanscan/logger"
	"github.com/spf13/cobra"
)

var VERSION = "v1.3.1"

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Prints version",
		Run: func(cmd *cobra.Command, args []string) {
			logger.New().Info().Msgf("go-lanscan: %s", VERSION)
		},
	}
}
