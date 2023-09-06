// SPDX-License-Identifier: GPL-3.0-or-later

package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/progress"
	"github.com/jedib0t/go-pretty/table"
	"github.com/robgonnella/go-lanscan/logger"
	"github.com/robgonnella/go-lanscan/network"
	"github.com/robgonnella/go-lanscan/scanner"
	"github.com/robgonnella/go-lanscan/util"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

type DeviceResult struct {
	IP        net.IP           `json:"ip"`
	MAC       net.HardwareAddr `json:"mac"`
	Vendor    string           `json:"vendor"`
	Status    scanner.Status   `json:"status"`
	OpenPorts []uint16         `json:"openPorts"`
}

func (r *DeviceResult) Serializable() interface{} {
	return struct {
		IP        string   `json:"ip"`
		MAC       string   `json:"mac"`
		Vendor    string   `json:"vendor"`
		Status    string   `json:"status"`
		OpenPorts []uint16 `json:"openPorts"`
	}{
		IP:        r.IP.String(),
		MAC:       r.MAC.String(),
		Vendor:    r.Vendor,
		Status:    string(r.Status),
		OpenPorts: r.OpenPorts,
	}
}

type Results struct {
	Devices   []*DeviceResult `json:"devices"`
	DeviceMux sync.Mutex
}

func (r *Results) MarshalJSON() ([]byte, error) {
	data := []interface{}{}

	for _, r := range r.Devices {
		data = append(data, r.Serializable())
	}

	return json.Marshal(data)
}

func NewRoot() (*cobra.Command, error) {
	var printJson bool
	var noProgress bool
	var ports string
	var idleTimeoutSeconds int
	var listenPort uint16
	var ifaceName string
	var targets []string
	var vendorInfo bool

	netInfo, err := network.GetNetworkInfo()

	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:   "go-lanscan",
		Short: "Scan your LAN!",
		Long:  `CLI to scan your Local Area Network`,
		RunE: func(cmd *cobra.Command, args []string) error {
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

			runner, err := newRootRunner(
				targets,
				netInfo,
				portList,
				listenPort,
				idleTimeoutSeconds,
				noProgress,
				printJson,
				vendorInfo,
			)

			if err != nil {
				return err
			}

			return runner.run()
		},
	}

	cmd.Flags().BoolVar(&printJson, "json", false, "output json instead of table text")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable all output except for final results")
	cmd.Flags().StringVarP(&ports, "ports", "p", "1-65535", "target ports")
	cmd.Flags().IntVar(&idleTimeoutSeconds, "idle-timeout", 5, "timeout when no expected packets are received for this duration")
	cmd.Flags().Uint16Var(&listenPort, "listen-port", 54321, "set the port on which the scanner will listen for packets")
	cmd.Flags().StringVarP(&ifaceName, "interface", "i", netInfo.Interface.Name, "set the interface for scanning")
	cmd.Flags().StringSliceVarP(&targets, "targets", "t", []string{netInfo.Cidr}, "set targets for scanning")
	cmd.Flags().BoolVar(&vendorInfo, "vendor", false, "include vendor info (takes a little longer)")

	cmd.AddCommand(newVersion())

	return cmd, nil
}

type rootRunner struct {
	idleTimeoutSeconds int
	printJson          bool
	vendorChan         chan *scanner.VendorResult
	noProgress         bool
	targets            []string
	totalTargets       int
	netInfo            *network.NetworkInfo
	totalHosts         int
	ports              []string
	listenPort         uint16
	results            *Results
	pw                 progress.Writer
	arpTracker         *progress.Tracker
	synTracker         *progress.Tracker
	arpResults         chan *scanner.ArpScanResult
	arpDone            chan bool
	synResults         chan *scanner.SynScanResult
	synDone            chan bool
	errorChan          chan error
	arpScanner         scanner.Scanner
	synScanner         scanner.Scanner
	log                logger.Logger
}

func newRootRunner(
	targets []string,
	netInfo *network.NetworkInfo,
	ports []string,
	listenPort uint16,
	idleTimeoutSeconds int,
	noProgress bool,
	printJson bool,
	vendorInfo bool,
) (*rootRunner, error) {
	arpResults := make(chan *scanner.ArpScanResult)
	arpDone := make(chan bool)

	arpScanner, err := scanner.NewArpScanner(
		targets,
		netInfo,
		arpResults,
		arpDone,
		scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeoutSeconds)),
	)

	if err != nil {
		return nil, err
	}

	pw := progressWriter()

	results := &Results{
		Devices:   []*DeviceResult{},
		DeviceMux: sync.Mutex{},
	}

	runner := &rootRunner{
		targets:            targets,
		netInfo:            netInfo,
		ports:              ports,
		listenPort:         listenPort,
		idleTimeoutSeconds: idleTimeoutSeconds,
		noProgress:         noProgress,
		printJson:          printJson,
		results:            results,
		pw:                 pw,
		totalTargets:       util.TotalTargets(targets),
		totalHosts:         util.IPHostTotal(netInfo.IPNet),
		arpTracker:         tracker(pw, "starting arp scan", true),
		synTracker:         tracker(pw, "starting syn scan", false),
		arpResults:         arpResults,
		arpDone:            arpDone,
		synResults:         make(chan *scanner.SynScanResult),
		synDone:            make(chan bool),
		arpScanner:         arpScanner,
		vendorChan:         make(chan *scanner.VendorResult),
		errorChan:          make(chan error),
		log:                logger.New(),
	}

	if vendorInfo {
		option := scanner.WithVendorInfo(runner.processVendorResult)
		option(runner.arpScanner)
	}

	if runner.totalTargets > 0 {
		runner.arpTracker.Total = int64(runner.totalTargets)
	} else {
		runner.arpTracker.Total = int64(runner.totalHosts)
	}

	if noProgress {
		logger.SetGlobalLevel(zerolog.Disabled)
	} else {
		arpScanner.SetRequestNotifications(runner.arpAttemptCallback)
	}

	return runner, nil
}

func (runner *rootRunner) run() error {
	start := time.Now()

	if !runner.noProgress {
		go runner.pw.Render()
	}

	// run in go routine so we can process in results in parallel
	go func() {
		if err := runner.arpScanner.Scan(); err != nil {
			runner.errorChan <- err
		}
	}()

	for {
		select {
		case err := <-runner.errorChan:
			return err
		case res := <-runner.arpResults:
			go runner.processArpResult(res)
		case <-runner.arpDone:
			go runner.processArpDone()
		case res := <-runner.synResults:
			go runner.processSynResult(res)
		case <-runner.synDone:
			runner.processSynDone(start)
			return nil
		}
	}
}

func (runner *rootRunner) processSynResult(result *scanner.SynScanResult) {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	targetIdx := slices.IndexFunc(runner.results.Devices, func(r *DeviceResult) bool {
		return r.IP.Equal(result.IP)
	})

	if targetIdx != -1 {
		target := runner.results.Devices[targetIdx]
		if !util.SliceIncludes(target.OpenPorts, result.Port.ID) {
			target.OpenPorts = append(
				target.OpenPorts,
				result.Port.ID,
			)

			slices.Sort(target.OpenPorts)

			runner.results.Devices[targetIdx] = target
		}
	}
}

func (runner *rootRunner) processSynDone(start time.Time) {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	runner.synScanner.Stop()

	if !runner.noProgress {
		runner.synTracker.Message = "syn - scan complete"
		runner.synTracker.Increment(10)
	}

	runner.printSynResults()

	runner.log.Info().Str("duration", time.Since(start).String()).Msg("lan scan complete")
}

func (runner *rootRunner) processArpResult(result *scanner.ArpScanResult) {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	targetIdx := slices.IndexFunc(runner.results.Devices, func(r *DeviceResult) bool {
		return r.IP.Equal(result.IP)
	})

	if targetIdx == -1 {
		runner.results.Devices = append(runner.results.Devices, &DeviceResult{
			IP:        result.IP,
			MAC:       result.MAC,
			Status:    scanner.StatusOnline,
			OpenPorts: []uint16{},
		})

		slices.SortFunc(runner.results.Devices, func(r1, r2 *DeviceResult) int {
			return bytes.Compare(r1.IP, r2.IP)
		})
	}
}

func (runner *rootRunner) processArpDone() {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	runner.arpScanner.Stop()

	if !runner.noProgress {
		runner.arpTracker.Message = "arp - scan complete"
		runner.arpTracker.Increment(10)
		runner.printArpResults()

		if len(runner.results.Devices) > 0 {
			runner.synTracker.Total = int64(
				len(runner.results.Devices) * util.PortTotal(runner.ports),
			)
			runner.pw.AppendTracker(runner.synTracker)
		}
	}

	synTargets := []*scanner.ArpScanResult{}

	for _, r := range runner.results.Devices {
		synTargets = append(synTargets, &scanner.ArpScanResult{
			IP:  r.IP,
			MAC: r.MAC,
		})
	}

	synScanner, err := scanner.NewSynScanner(
		synTargets,
		runner.netInfo,
		runner.ports,
		runner.listenPort,
		runner.synResults,
		runner.synDone,
		scanner.WithIdleTimeout(time.Second*time.Duration(runner.idleTimeoutSeconds)),
	)

	if err != nil {
		go func() {
			runner.errorChan <- err
		}()
	}

	if !runner.noProgress {
		synScanner.SetRequestNotifications(runner.synAttemptCallback)
	}

	runner.synScanner = synScanner

	if len(runner.results.Devices) == 0 {
		go func() {
			runner.synDone <- true
		}()

		return
	}

	// run in goroutine so we can process results in parallel
	if err := synScanner.Scan(); err != nil {
		go func() {
			runner.errorChan <- err
		}()
	}
}

func (runner *rootRunner) processVendorResult(result *scanner.VendorResult) {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	for i, r := range runner.results.Devices {
		if r.MAC.String() == result.MAC.String() {
			r.Vendor = result.Vendor
			runner.results.Devices[i] = r
			break
		}
	}
}

func (runner *rootRunner) arpAttemptCallback(a *scanner.Request) {
	message := fmt.Sprintf("arp - scanning %s", a.IP)

	runner.arpTracker.Message = message
	runner.arpTracker.Increment(1)

	if runner.arpTracker.IsDone() {
		runner.arpTracker.Message = "arp - scan complete - compiling results"
	}
}

func (runner *rootRunner) synAttemptCallback(a *scanner.Request) {
	message := fmt.Sprintf("syn - scanning port %d on %s", a.Port, a.IP)
	runner.synTracker.Message = message
	runner.synTracker.Increment(1)
	if runner.synTracker.IsDone() {
		runner.synTracker.Message = "syn - scan complete - compiling results"
	}
}

func (runner *rootRunner) printArpResults() {
	if runner.printJson {
		data, err := runner.results.MarshalJSON()

		if err != nil {
			go func() {
				runner.errorChan <- err
			}()
		}

		fmt.Println(string(data))
		return
	}

	var arpTable = table.NewWriter()
	arpTable.SetOutputMirror(os.Stdout)
	arpTable.AppendHeader(table.Row{"IP", "MAC", "VENDOR"})

	for _, t := range runner.results.Devices {
		arpTable.AppendRow(table.Row{t.IP.String(), t.MAC.String(), t.Vendor})
	}

	arpTable.Render()
}

func (runner *rootRunner) printSynResults() {
	if runner.printJson {
		data, err := runner.results.MarshalJSON()

		if err != nil {
			go func() {
				runner.errorChan <- err
			}()
		}

		fmt.Println(string(data))
		return
	}

	var synTable = table.NewWriter()
	synTable.SetOutputMirror(os.Stdout)
	synTable.AppendHeader(table.Row{"IP", "MAC", "VENDOR", "STATUS", "OPEN PORTS"})

	for _, r := range runner.results.Devices {
		synTable.AppendRow(table.Row{
			r.IP.String(),
			r.MAC.String(),
			r.Vendor,
			r.Status,
			r.OpenPorts,
		})
	}

	synTable.Render()

}

// helpers
func progressWriter() progress.Writer {
	pw := progress.NewWriter()
	pw.SetOutputWriter(os.Stdout)
	pw.SetAutoStop(false)
	pw.SetTrackerLength(25)
	pw.SetMessageWidth(47)
	pw.SetNumTrackersExpected(1)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 100)
	pw.Style().Colors = progress.StyleColorsExample
	pw.Style().Options.PercentFormat = "%4.3f%%"

	return pw
}

func tracker(pw progress.Writer, message string, attach bool) *progress.Tracker {
	tracker := &progress.Tracker{Message: message}

	if attach {
		pw.AppendTracker(tracker)
	}

	return tracker
}
