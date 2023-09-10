// SPDX-License-Identifier: GPL-3.0-or-later

package command

import (
	"io"
	"net/http"
	"os"
	"path"

	"github.com/robgonnella/go-lanscan/logger"
	"github.com/spf13/cobra"
)

func newUpdateVendors() *cobra.Command {
	return &cobra.Command{
		Use:   "update-vendors",
		Short: "Updates static vendors database",
		Long: `Updates the static file used for vendor lookups. This file can
		be found at ~/.config/go-lanscan/oui.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()

			if err != nil {
				return err
			}

			dir := path.Join(home, ".config", "go-lanscan")
			ouiTxt := path.Join(dir, "oui.txt")

			logger.New().Info().Str("file", ouiTxt).Msg("updating vendor database")

			resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")

			if err != nil {
				return err
			}

			data, err := io.ReadAll(resp.Body)

			if err != nil {
				return err
			}

			if err := os.MkdirAll(dir, 0751); err != nil {
				return err
			}

			file, err := os.OpenFile(ouiTxt, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

			if err != nil {
				return err
			}

			defer file.Close()

			_, err = file.Write(data)

			return err
		},
	}
}
