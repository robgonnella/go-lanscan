// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/progress"
	"github.com/jedib0t/go-pretty/table"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
)

type DeviceResult struct {
	IP        net.IP           `json:"ip"`
	MAC       net.HardwareAddr `json:"mac"`
	Vendor    string           `json:"vendor"`
	Status    scanner.Status   `json:"status"`
	OpenPorts []scanner.Port   `json:"openPorts"`
}

func (r *DeviceResult) Serializable() interface{} {
	return struct {
		IP        string         `json:"ip"`
		MAC       string         `json:"mac"`
		Vendor    string         `json:"vendor"`
		Status    string         `json:"status"`
		OpenPorts []scanner.Port `json:"openPorts"`
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
	var accuracy string

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

			runner := newRootRunner(
				accuracy,
				targets,
				netInfo,
				portList,
				listenPort,
				idleTimeoutSeconds,
				noProgress,
				printJson,
				vendorInfo,
			)

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
	cmd.Flags().StringVar(&accuracy, "accuracy", "high", "sets throttle to ensure fewer packets are dropped. Valid values are high (slower more accurate), medium, low (faster less accurate)")
	cmd.Flags().BoolVar(&vendorInfo, "vendor", false, "include vendor info (takes a little longer)")

	cmd.AddCommand(newVersion())
	cmd.AddCommand(newUpdateVendors())

	return cmd, nil
}

type rootRunner struct {
	idleTimeoutSeconds int
	printJson          bool
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
	scanResults        chan *scanner.ScanResult
	errorChan          chan error
	scanner            scanner.Scanner
	log                logger.Logger
}

func newRootRunner(
	accuracy string,
	targets []string,
	netInfo *network.NetworkInfo,
	ports []string,
	listenPort uint16,
	idleTimeoutSeconds int,
	noProgress bool,
	printJson bool,
	vendorInfo bool,
) *rootRunner {
	var scannerAccuracy scanner.Accuracy

	switch strings.ToLower(accuracy) {
	case "low":
		scannerAccuracy = scanner.LOW_ACCURACY
	case "medium":
		scannerAccuracy = scanner.MEDIUM_ACCURACY
	case "high":
		scannerAccuracy = scanner.HIGH_ACCURACY
	default:
		scannerAccuracy = scanner.HIGH_ACCURACY
	}

	scanResults := make(chan *scanner.ScanResult)

	fullScanner := scanner.NewFullScanner(
		netInfo,
		targets,
		ports,
		listenPort,
		scanResults,
		scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeoutSeconds)),
		scanner.WithVendorInfo(vendorInfo),
		scanner.WithAccuracy(scannerAccuracy),
	)

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
		scanResults:        scanResults,
		scanner:            fullScanner,
		errorChan:          make(chan error),
		log:                logger.New(),
	}

	if runner.totalTargets > 0 {
		runner.arpTracker.Total = int64(runner.totalTargets)
	} else {
		runner.arpTracker.Total = int64(runner.totalHosts)
	}

	if noProgress {
		logger.SetGlobalLevel(zerolog.Disabled)
	} else {
		fullScanner.SetRequestNotifications(runner.requestCallback)
	}

	return runner
}

func (runner *rootRunner) run() error {
	start := time.Now()

	if !runner.noProgress {
		go runner.pw.Render()
	}

	// run in go routine so we can process in results in parallel
	go func() {
		if err := runner.scanner.Scan(); err != nil {
			runner.errorChan <- err
		}
	}()

	for {
		select {
		case err := <-runner.errorChan:
			return err
		case res := <-runner.scanResults:
			switch res.Type {
			case scanner.ARPResult:
				go runner.processArpResult(res.Payload.(*scanner.ArpScanResult))
			case scanner.ARPDone:
				go runner.processArpDone()
			case scanner.SYNResult:
				go runner.processSynResult(res.Payload.(*scanner.SynScanResult))
			case scanner.SYNDone:
				runner.processSynDone(start)
				return nil
			}
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
		exists := util.SliceIncludesFunc(target.OpenPorts, func(p scanner.Port, i int) bool {
			return p.ID == result.Port.ID
		})

		if !exists {
			target.OpenPorts = append(
				target.OpenPorts,
				result.Port,
			)

			slices.SortFunc(target.OpenPorts, func(p1, p2 scanner.Port) int {
				if int(p1.ID) < int(p2.ID) {
					return -1
				}

				if int(p1.ID) > int(p2.ID) {
					return 1
				}

				return 0
			})

			runner.results.Devices[targetIdx] = target
		}
	}
}

func (runner *rootRunner) processSynDone(start time.Time) {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	runner.scanner.Stop()
	runner.printSynResults()

	runner.log.Info().Str("duration", time.Since(start).String()).Msg("go-lanscan complete")
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
			Vendor:    result.Vendor,
			OpenPorts: []scanner.Port{},
		})

		slices.SortFunc(runner.results.Devices, func(r1, r2 *DeviceResult) int {
			return bytes.Compare(r1.IP, r2.IP)
		})
	}
}

func (runner *rootRunner) processArpDone() {
	runner.results.DeviceMux.Lock()
	defer runner.results.DeviceMux.Unlock()

	if !runner.noProgress {
		runner.printArpResults()

		if len(runner.results.Devices) > 0 {
			runner.synTracker.Total = int64(
				len(runner.results.Devices) * util.PortTotal(runner.ports),
			)
			runner.pw.AppendTracker(runner.synTracker)
		}
	}

	if len(runner.results.Devices) == 0 {
		go func() {
			runner.scanResults <- &scanner.ScanResult{
				Type: scanner.SYNDone,
			}
		}()

		return
	}
}

func (runner *rootRunner) requestCallback(r *scanner.Request) {
	if r.Type == scanner.ArpRequest {
		message := fmt.Sprintf("arp - scanning %s", r.IP)

		runner.arpTracker.Message = message
		runner.arpTracker.Increment(1)

		if runner.arpTracker.IsDone() {
			runner.arpTracker.Message = "arp - scan complete"
			go func() {
				// for some reason this needs to run in a goroutine with a delay
				// otherwise the tracker output prevents this log line from printing
				time.Sleep(time.Millisecond * 100)
				runner.log.Info().Msg("compiling arp results...")
			}()
		}
	}

	if r.Type == scanner.SynRequest {
		message := fmt.Sprintf("syn - scanning port %d on %s", r.Port, r.IP)
		runner.synTracker.Message = message
		runner.synTracker.Increment(1)
		if runner.synTracker.IsDone() {
			runner.synTracker.Message = "syn - scan complete"
			go func() {
				// for some reason this needs to run in a goroutine with a delay
				// otherwise the tracker output prevents this log line from printing
				time.Sleep(time.Millisecond * 100)
				runner.log.Info().Msg("compiling syn results...")
			}()
		}
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
		openPorts := []string{}

		for _, p := range r.OpenPorts {
			openPorts = append(openPorts, fmt.Sprintf("%s:%d", p.Service, p.ID))
		}

		synTable.AppendRow(table.Row{
			r.IP.String(),
			r.MAC.String(),
			r.Vendor,
			r.Status,
			openPorts,
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
