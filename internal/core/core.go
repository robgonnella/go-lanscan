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

	"github.com/jedib0t/go-pretty/progress"
	"github.com/jedib0t/go-pretty/table"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/rs/zerolog"
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
	Devices []*DeviceResult `json:"devices"`
}

func (r *Results) MarshalJSON() ([]byte, error) {
	data := []interface{}{}

	for _, r := range r.Devices {
		data = append(data, r.Serializable())
	}

	return json.Marshal(data)
}

type Core struct {
	arpOnly         bool
	printJson       bool
	noProgress      bool
	outFile         string
	portLen         int
	results         *Results
	pw              progress.Writer
	arpTracker      *progress.Tracker
	synTracker      *progress.Tracker
	requestNotifier chan *scanner.Request
	errorChan       chan error
	scanner         scanner.Scanner
	mux             *sync.RWMutex
	log             logger.Logger
}

func New() *Core {
	return &Core{
		requestNotifier: make(chan *scanner.Request),
		mux:             &sync.RWMutex{},
		log:             logger.New(),
	}
}

func (c *Core) Initialize(
	coreScanner scanner.Scanner,
	targetLen int,
	portLen int,
	noProgress bool,
	arpOnly bool,
	printJson bool,
	outFile string,
) {
	pw := progressWriter()

	results := &Results{
		Devices: []*DeviceResult{},
	}

	arpTracker := &progress.Tracker{Message: "starting arp scan"}
	arpTracker.Total = int64(targetLen)

	if noProgress {
		logger.SetGlobalLevel(zerolog.Disabled)
	} else {
		coreScanner.SetRequestNotifications(c.requestNotifier)
	}

	c.scanner = coreScanner
	c.results = results
	c.errorChan = make(chan error)
	c.portLen = portLen
	c.pw = pw
	c.arpTracker = arpTracker
	c.synTracker = &progress.Tracker{Message: "starting syn scan"}
	c.noProgress = noProgress
	c.arpOnly = arpOnly
	c.printJson = printJson
	c.outFile = outFile
}

func (c *Core) Run() error {
	start := time.Now()

	if !c.noProgress {
		c.pw.AppendTracker(c.arpTracker)
		go c.monitorRequestNotifications()
		go c.pw.Render()
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
		c.synTracker.Total = int64(
			len(c.results.Devices) * c.portLen,
		)
		c.pw.AppendTracker(c.synTracker)
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

	if c.printJson {
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

	if c.printJson {
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
			c.arpTracker.Increment(1)

			message := fmt.Sprintf("arp - scanning %s", r.IP)

			if c.arpTracker.IsDone() {
				message = "arp - scan complete"
				// delay to print line after message is updated
				time.AfterFunc(time.Millisecond*100, func() {
					c.log.Info().Msg("compiling arp results...")
				})
			}

			c.arpTracker.Message = message
		case scanner.SynRequest:
			c.synTracker.Increment(1)

			message := fmt.Sprintf(
				"syn - scanning port %d on %s",
				r.Port,
				r.IP,
			)

			if c.synTracker.IsDone() {
				message = "syn - scan complete"
				// delay to print line after message is updated
				time.AfterFunc(time.Millisecond*100, func() {
					c.log.Info().Msg("compiling syn results...")
				})
			}

			c.synTracker.Message = message
		}
	}
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
