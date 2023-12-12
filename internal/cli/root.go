// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
)

func Root(
	runner core.Runner,
	userNet network.Network,
	vendorRepo oui.VendorRepo,
) (*cobra.Command, error) {
	var printJson bool
	var noProgress bool
	var ports string
	var idleTimeoutSeconds int
	var listenPort uint16
	var ifaceName string
	var targets []string
	var vendorInfo bool
	var arpOnly bool
	var outFile string

	cmd := &cobra.Command{
		Use:   "go-lanscan",
		Short: "Scan your LAN!",
		Long:  `CLI to scan your Local Area Network`,
		RunE: func(cmd *cobra.Command, args []string) error {
			portList := strings.Split(ports, ",")

			if ifaceName != userNet.Interface().Name {
				uNet, err := network.NewNetworkFromInterfaceName(ifaceName)

				if err != nil {
					return err
				}

				userNet = uNet
			}

			if len(targets) == 1 && targets[0] == userNet.Cidr() {
				targets = []string{}
			}

			var coreScanner scanner.Scanner

			if arpOnly {
				coreScanner = scanner.NewArpScanner(
					targets,
					userNet,
					scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeoutSeconds)),
				)
			} else {
				coreScanner = scanner.NewFullScanner(
					userNet,
					targets,
					portList,
					listenPort,
					scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeoutSeconds)),
				)
			}

			if vendorInfo {
				coreScanner.IncludeVendorInfo(vendorRepo)
			}

			portLen := util.PortTotal(portList)

			targetLen := util.TotalTargets(targets)

			if targetLen == 0 {
				targetLen = util.IPHostTotal(userNet.IPNet())
			}

			runner.Initialize(
				coreScanner,
				targetLen,
				portLen,
				noProgress,
				arpOnly,
				printJson,
				outFile,
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
	cmd.Flags().StringVarP(&ifaceName, "interface", "i", userNet.Interface().Name, "set the interface for scanning")
	cmd.Flags().StringSliceVarP(&targets, "targets", "t", []string{userNet.Cidr()}, "set targets for scanning")
	cmd.Flags().StringVar(&outFile, "out-file", "", "outputs final report to file")
	cmd.Flags().BoolVar(&vendorInfo, "vendor", false, "include vendor info (takes a little longer)")

	cmd.AddCommand(newVersion())
	cmd.AddCommand(newUpdateVendors(vendorRepo))

	return cmd, nil
}
