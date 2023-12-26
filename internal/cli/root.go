// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"

	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
)

func printConfiguration(
	coreScanner scanner.Scanner,
	targets []string,
	cidr string,
	ports []string,
	ifaceName string,
	listenPort uint16,
	timing string,
	vendorInfo,
	printJSON,
	arpOnly,
	progress bool,
	outFile string,
) {
	var configTable = table.NewWriter()

	configTable.SetOutputMirror(os.Stdout)

	configTable.AppendRow(table.Row{
		"scannerType",
		fmt.Sprintf("%T", coreScanner),
	})

	configTable.AppendRow(table.Row{
		"targets",
		targets,
	})

	configTable.AppendRow(table.Row{
		"cidr",
		cidr,
	})

	configTable.AppendRow(table.Row{
		"ports",
		ports,
	})

	configTable.AppendRow(table.Row{
		"interface",
		ifaceName,
	})

	configTable.AppendRow(table.Row{
		"listenPort",
		listenPort,
	})

	configTable.AppendRow(table.Row{
		"timing",
		timing,
	})

	configTable.AppendRow(table.Row{
		"vendorInfo",
		vendorInfo,
	})

	configTable.AppendRow(table.Row{
		"json",
		printJSON,
	})

	configTable.AppendRow(table.Row{
		"arpOnly",
		arpOnly,
	})

	configTable.AppendRow(table.Row{
		"progress",
		progress,
	})

	configTable.AppendRow(table.Row{
		"outFile",
		outFile,
	})

	configTable.Render()
}

// Root returns root command for cli
func Root(
	runner core.Runner,
	userNet network.Network,
	vendorRepo oui.VendorRepo,
) (*cobra.Command, error) {
	var printJSON bool
	var noProgress bool
	var ports []string
	var timing string
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
			log := logger.New()

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
					ports,
					listenPort,
					scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeoutSeconds)),
				)
			}

			if vendorInfo {
				coreScanner.IncludeVendorInfo(vendorRepo)
			}

			timingDuration, err := time.ParseDuration(timing)

			if err != nil {
				log.Error().Err(err).Msg("invalid timing value")
				return err
			}

			coreScanner.SetTiming(timingDuration)

			portLen := util.PortTotal(ports)

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
				printJSON,
				outFile,
			)

			if !noProgress {
				printConfiguration(
					coreScanner,
					targets,
					userNet.Cidr(),
					ports,
					userNet.Interface().Name,
					listenPort,
					timing,
					vendorInfo,
					printJSON,
					arpOnly,
					!noProgress,
					outFile,
				)
			}

			return runner.Run()
		},
	}

	cmd.Flags().StringVar(&timing, "timing", "100µs", "set time between packet sends - the faster you send the less accurate the result will be")
	cmd.Flags().BoolVar(&printJSON, "json", false, "output json instead of table text")
	cmd.Flags().BoolVar(&arpOnly, "arp-only", false, "only perform arp scanning (skip syn scanning)")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable all output except for final results")
	cmd.Flags().StringSliceVarP(&ports, "ports", "p", []string{"1-65535"}, "target ports")
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
