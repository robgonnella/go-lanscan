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

type Core struct {
	arpOnly     bool
	printJson   bool
	noProgress  bool
	portLen     int
	results     *Results
	pw          progress.Writer
	arpTracker  *progress.Tracker
	synTracker  *progress.Tracker
	scanResults chan *scanner.ScanResult
	errorChan   chan error
	scanner     scanner.Scanner
	log         logger.Logger
}

func New() *Core {
	return &Core{
		log: logger.New(),
	}
}

func (c *Core) Initialize(
	coreScanner scanner.Scanner,
	scanResults chan *scanner.ScanResult,
	targetLen int,
	portLen int,
	noProgress bool,
	arpOnly bool,
	printJson bool,
) {
	pw := progressWriter()

	results := &Results{
		Devices:   []*DeviceResult{},
		DeviceMux: sync.Mutex{},
	}

	arpTracker := tracker(pw, "starting arp scan", true)
	arpTracker.Total = int64(targetLen)

	if noProgress {
		logger.SetGlobalLevel(zerolog.Disabled)
	} else {
		coreScanner.SetRequestNotifications(c.requestCallback)
	}

	c.scanner = coreScanner
	c.scanResults = scanResults
	c.results = results
	c.errorChan = make(chan error)
	c.portLen = portLen
	c.pw = pw
	c.arpTracker = arpTracker
	c.synTracker = tracker(pw, "starting syn scan", false)
	c.noProgress = noProgress
	c.arpOnly = arpOnly
	c.printJson = printJson
}

func (c *Core) Run() error {
	start := time.Now()

	if !c.noProgress {
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
		case res := <-c.scanResults:
			switch res.Type {
			case scanner.ARPResult:
				go c.processArpResult(res.Payload.(*scanner.ArpScanResult))
			case scanner.ARPDone:
				go c.processArpDone()
				if c.arpOnly {
					c.printArpResults()
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

	c.scanner.Stop()

	c.log.Info().Str("duration", time.Since(start).String()).Msg("go-lanscan complete")

	return nil
}

func (c *Core) processSynResult(result *scanner.SynScanResult) {
	c.results.DeviceMux.Lock()
	defer c.results.DeviceMux.Unlock()

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
	c.results.DeviceMux.Lock()
	defer c.results.DeviceMux.Unlock()

	c.printSynResults()
}

func (c *Core) processArpResult(result *scanner.ArpScanResult) {
	c.results.DeviceMux.Lock()
	defer c.results.DeviceMux.Unlock()

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
	if c.arpOnly {
		return
	}

	c.results.DeviceMux.Lock()
	defer c.results.DeviceMux.Unlock()

	if !c.noProgress {
		c.printArpResults()

		if !c.arpOnly && len(c.results.Devices) > 0 {
			c.synTracker.Total = int64(
				len(c.results.Devices) * c.portLen,
			)
			c.pw.AppendTracker(c.synTracker)
		}
	}

	if !c.arpOnly && len(c.results.Devices) == 0 {
		go func() {
			c.scanResults <- &scanner.ScanResult{
				Type: scanner.SYNDone,
			}
		}()

		return
	}
}

func (c *Core) requestCallback(r *scanner.Request) {
	if r.Type == scanner.ArpRequest {
		message := fmt.Sprintf("arp - scanning %s", r.IP)

		c.arpTracker.Message = message
		c.arpTracker.Increment(1)

		if c.arpTracker.IsDone() {
			c.arpTracker.Message = "arp - scan complete"
			go func() {
				// for some reason this needs to run in a goroutine with a delay
				// otherwise the tracker output prevents this log line from printing
				time.Sleep(time.Millisecond * 100)
				c.log.Info().Msg("compiling arp results...")
			}()
		}
	}

	if r.Type == scanner.SynRequest {
		message := fmt.Sprintf("syn - scanning port %d on %s", r.Port, r.IP)
		c.synTracker.Message = message
		c.synTracker.Increment(1)
		if c.synTracker.IsDone() {
			c.synTracker.Message = "syn - scan complete"
			go func() {
				// for some reason this needs to run in a goroutine with a delay
				// otherwise the tracker output prevents this log line from printing
				time.Sleep(time.Millisecond * 100)
				c.log.Info().Msg("compiling syn results...")
			}()
		}
	}
}

func (c *Core) printArpResults() {
	if c.printJson {
		data, err := c.results.MarshalJSON()

		if err != nil {
			go func() {
				c.errorChan <- err
			}()
		}

		fmt.Println(string(data))
		return
	}

	var arpTable = table.NewWriter()
	arpTable.SetOutputMirror(os.Stdout)
	arpTable.AppendHeader(table.Row{"IP", "MAC", "VENDOR"})

	for _, t := range c.results.Devices {
		arpTable.AppendRow(table.Row{t.IP.String(), t.MAC.String(), t.Vendor})
	}

	arpTable.Render()
}

func (c *Core) printSynResults() {
	if c.printJson {
		data, err := c.results.MarshalJSON()

		if err != nil {
			go func() {
				c.errorChan <- err
			}()
		}

		fmt.Println(string(data))
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
