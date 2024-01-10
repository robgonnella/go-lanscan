// SPDX-License-Identifier: GPL-3.0-or-later

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
)

// DeviceResult represents a discovered network device
type DeviceResult struct {
	IP        net.IP           `json:"ip"`
	MAC       net.HardwareAddr `json:"mac"`
	Vendor    string           `json:"vendor"`
	Status    scanner.Status   `json:"status"`
	OpenPorts []scanner.Port   `json:"openPorts"`
}

// Serializable returns a serializable version of DeviceResult
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

// Results data structure for holding discovered network devices
type Results struct {
	Devices []*DeviceResult `json:"devices"`
}

// MarshalJSON returns marshaled JSON of Results
func (r *Results) MarshalJSON() ([]byte, error) {
	data := []interface{}{}

	for _, r := range r.Devices {
		data = append(data, r.Serializable())
	}

	return json.Marshal(data)
}

// Core implements the Runner interface for performing network scanning
type Core struct {
	arpOnly         bool
	printJSON       bool
	noProgress      bool
	outFile         string
	portLen         int
	results         *Results
	arpProgress     *progressbar.ProgressBar
	synProgress     *progressbar.ProgressBar
	requestNotifier chan *scanner.Request
	errorChan       chan error
	scanner         scanner.Scanner
	mux             *sync.RWMutex
	log             logger.Logger
}

// New returns a new instance of Core
func New() *Core {
	return &Core{
		requestNotifier: make(chan *scanner.Request),
		mux:             &sync.RWMutex{},
		log:             logger.New(),
	}
}

// Initialize initializes the Core before performing network scanning
func (c *Core) Initialize(
	coreScanner scanner.Scanner,
	targetLen int,
	portLen int,
	noProgress bool,
	arpOnly bool,
	printJSON bool,
	outFile string,
) {
	results := &Results{
		Devices: []*DeviceResult{},
	}

	if noProgress {
		logger.SetGlobalLevel(zerolog.Disabled)
	} else {
		coreScanner.SetRequestNotifications(c.requestNotifier)
	}

	c.scanner = coreScanner
	c.results = results
	c.errorChan = make(chan error)
	c.portLen = portLen
	c.arpProgress = newProgressBar(targetLen, "performing arp scan")
	c.synProgress = newProgressBar(1, "performing syn scan")
	c.noProgress = noProgress
	c.arpOnly = arpOnly
	c.printJSON = printJSON
	c.outFile = outFile
}

// Run executes a network scan
func (c *Core) Run() error {
	start := time.Now()

	if !c.noProgress {
		go c.monitorRequestNotifications()
	}

	// run in go routine so we can process in results in parallel
	go func() {
		if err := c.scanner.Scan(); err != nil {
			c.errorChan <- err
		}
	}()

OUTER:
	for {
		select {
		case err := <-c.errorChan:
			return err
		case res := <-c.scanner.Results():
			switch res.Type {
			case scanner.ARPResult:
				go c.processArpResult(res.Payload.(*scanner.ArpScanResult))
			case scanner.ARPDone:
				c.processArpDone()
				if c.arpOnly {
					break OUTER
				}
			case scanner.SYNResult:
				go c.processSynResult(res.Payload.(*scanner.SynScanResult))
			case scanner.SYNDone:
				c.processSynDone()
				break OUTER
			}
		}
	}

	c.log.Info().Str("duration", time.Since(start).String()).Msg("go-lanscan complete")

	return nil
}

func (c *Core) processSynResult(result *scanner.SynScanResult) {
	c.mux.Lock()
	defer c.mux.Unlock()

	targetIdx := slices.IndexFunc(c.results.Devices, func(r *DeviceResult) bool {
		return r.IP.Equal(result.IP)
	})

	if targetIdx != -1 {
		target := c.results.Devices[targetIdx]
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

			c.results.Devices[targetIdx] = target
		}
	}
}

func (c *Core) processSynDone() {
	c.printSynResults()
}

func (c *Core) processArpResult(result *scanner.ArpScanResult) {
	c.mux.Lock()
	defer c.mux.Unlock()

	targetIdx := slices.IndexFunc(c.results.Devices, func(r *DeviceResult) bool {
		return r.IP.Equal(result.IP)
	})

	if targetIdx == -1 {
		c.results.Devices = append(c.results.Devices, &DeviceResult{
			IP:        result.IP,
			MAC:       result.MAC,
			Status:    scanner.StatusOnline,
			Vendor:    result.Vendor,
			OpenPorts: []scanner.Port{},
		})

		slices.SortFunc(c.results.Devices, func(r1, r2 *DeviceResult) int {
			return bytes.Compare(r1.IP, r2.IP)
		})
	}
}

func (c *Core) processArpDone() {
	c.mux.RLock()
	defer c.mux.RUnlock()

	c.printArpResults()

	if !c.noProgress && !c.arpOnly && len(c.results.Devices) > 0 {
		size := len(c.results.Devices) * c.portLen
		c.synProgress.ChangeMax(size)
	}

	if !c.arpOnly && len(c.results.Devices) == 0 {
		go func() {
			c.scanner.Results() <- &scanner.ScanResult{
				Type: scanner.SYNDone,
			}
		}()

		return
	}
}

func (c *Core) printArpResults() {
	c.mux.RLock()
	defer c.mux.RUnlock()

	if c.printJSON {
		data, err := c.results.MarshalJSON()

		if err != nil {
			go func() {
				c.errorChan <- err
			}()
		}

		if !c.noProgress {
			fmt.Println(string(data))
		}

		if c.arpOnly && c.outFile != "" {
			if err := os.WriteFile(c.outFile, data, 0644); err != nil {
				c.log.Error().Err(err).Msg("failed to write output report")
			}
		}

		return
	}

	var arpTable = table.NewWriter()
	arpTable.SetOutputMirror(os.Stdout)
	arpTable.AppendHeader(table.Row{"IP", "MAC", "VENDOR"})

	for _, t := range c.results.Devices {
		arpTable.AppendRow(table.Row{t.IP.String(), t.MAC.String(), t.Vendor})
	}

	output := arpTable.Render()

	if c.arpOnly && c.outFile != "" {
		if err := os.WriteFile(c.outFile, []byte(output), 0644); err != nil {
			c.log.Error().Err(err).Msg("failed to write output report")
		}

	}
}

func (c *Core) printSynResults() {
	c.mux.RLock()
	defer c.mux.RUnlock()

	if c.printJSON {
		data, err := c.results.MarshalJSON()

		if err != nil {
			go func() {
				c.errorChan <- err
			}()
		}

		fmt.Println(string(data))

		if c.outFile != "" {
			if err := os.WriteFile(c.outFile, data, 0644); err != nil {
				c.log.Error().Err(err).Msg("failed to write output report")
			}
		}

		return
	}

	var synTable = table.NewWriter()
	synTable.SetOutputMirror(os.Stdout)
	synTable.AppendHeader(table.Row{"IP", "MAC", "VENDOR", "STATUS", "OPEN PORTS"})

	for _, r := range c.results.Devices {
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

	output := synTable.Render()

	if c.outFile != "" {
		if err := os.WriteFile(c.outFile, []byte(output), 0644); err != nil {
			c.log.Error().Err(err).Msg("failed to write output report")
		}
	}
}

func (c *Core) monitorRequestNotifications() {
	for r := range c.requestNotifier {
		switch r.Type {
		case scanner.ArpRequest:
			// nolint:errcheck
			c.arpProgress.Add(1)

			message := fmt.Sprintf("arp - scanning %s", r.IP)

			c.arpProgress.Describe("\033[36m" + message + "\033[0m")

			if c.arpProgress.IsFinished() {
				// nolint:errcheck
				c.arpProgress.Clear()
				c.log.Info().Msg("compiling arp results...")
			}
		case scanner.SynRequest:
			// nolint:errcheck
			c.synProgress.Add(1)

			message := fmt.Sprintf(
				"syn - scanning port %d on %s",
				r.Port,
				r.IP,
			)

			c.synProgress.Describe("\033[36m" + message + "\033[0m")

			if c.synProgress.IsFinished() {
				// nolint:errcheck
				c.synProgress.Clear()
				c.log.Info().Msg("compiling syn results...")
			}
		}
	}
}

func newProgressBar(size int, msg string) *progressbar.ProgressBar {
	return progressbar.NewOptions(size,
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(25),
		progressbar.OptionSetDescription("\033[36m"+msg+"\033[0m"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
}
