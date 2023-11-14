// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/pkg/vendor"
	"github.com/spf13/cobra"
)

func newUpdateVendors(vendorRepo vendor.VendorRepo) *cobra.Command {
	return &cobra.Command{
		Use:   "update-vendors",
		Short: "Updates static vendors database",
		Long: `Updates the static file used for vendor lookups. This file can
		be found at ~/.config/go-lanscan/oui.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.New().
				Info().
				Msg("updating vendor database")

			return vendorRepo.UpdateVendors()
		},
	}
}
