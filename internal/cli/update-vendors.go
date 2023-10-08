// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/spf13/cobra"
)

func newUpdateVendors() *cobra.Command {
	return &cobra.Command{
		Use:   "update-vendors",
		Short: "Updates static vendors database",
		Long: `Updates the static file used for vendor lookups. This file can
		be found at ~/.config/go-lanscan/oui.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {

			ouiTxt, err := util.GetDefaultOuiTxtPath()

			if err != nil {
				return err
			}

			logger.New().
				Info().
				Str("file", *ouiTxt).
				Msg("updating vendor database")

			return util.UpdateStaticVendors(*ouiTxt)
		},
	}
}
