// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"errors"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
)

func Root(runner core.Runner) (*cobra.Command, error) {
	var printJson bool
	var noProgress bool
	var ports string
	var idleTimeoutSeconds int
	var listenPort uint16
	var ifaceName string
	var targets []string
	var vendorInfo bool
	var accuracy string
	var arpOnly bool

	netInfo, err := network.GetNetworkInfo()

	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:   "go-lanscan",
		Short: "Scan your LAN!",
		Long:  `CLI to scan your Local Area Network`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.New()

			ouiTxt, err := util.GetDefaultOuiTxtPath()

			if err != nil {
				return err
			}

			if _, err := os.Stat(*ouiTxt); errors.Is(err, os.ErrNotExist) {
				log.Info().
					Str("file", *ouiTxt).
					Msg("updating vendor database")
				if err := util.UpdateStaticVendors(*ouiTxt); err != nil {
					return err
				}
			}

			portList := strings.Split(ports, ",")

			if ifaceName != netInfo.Interface.Name {
				netInfo, err = network.GetNetworkInfoFromInterface(ifaceName)

				if err != nil {
					return err
				}
			}

			if len(targets) == 1 && targets[0] == netInfo.Cidr {
				targets = []string{}
			}

			runner.Initialize(
				accuracy,
				targets,
				netInfo,
				portList,
				listenPort,
				idleTimeoutSeconds,
				noProgress,
				printJson,
				vendorInfo,
				arpOnly,
			)

			return runner.Run()
		},
	}

	cmd.Flags().BoolVar(&printJson, "json", false, "output json instead of table text")
	cmd.Flags().BoolVar(&arpOnly, "arp-only", false, "only perform arp scanning (skip syn scanning)")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable all output except for final results")
	cmd.Flags().StringVarP(&ports, "ports", "p", "1-65535", "target ports")
	cmd.Flags().IntVar(&idleTimeoutSeconds, "idle-timeout", 5, "timeout when no expected packets are received for this duration")
	cmd.Flags().Uint16Var(&listenPort, "listen-port", 54321, "set the port on which the scanner will listen for packets")
	cmd.Flags().StringVarP(&ifaceName, "interface", "i", netInfo.Interface.Name, "set the interface for scanning")
	cmd.Flags().StringSliceVarP(&targets, "targets", "t", []string{netInfo.Cidr}, "set targets for scanning")
	cmd.Flags().StringVar(&accuracy, "accuracy", "high", "sets throttle to ensure fewer packets are dropped. Valid values are high (slower more accurate), medium, low (faster less accurate)")
	cmd.Flags().BoolVar(&vendorInfo, "vendor", false, "include vendor info (takes a little longer)")

	cmd.AddCommand(newVersion())
	cmd.AddCommand(newUpdateVendors())

	return cmd, nil
}
