// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

type FullScanner struct {
	ctx         context.Context
	cancel      context.CancelFunc
	targets     []string
	ports       []string
	listenPort  uint16
	netInfo     network.Network
	devices     []*ArpScanResult
	arpScanner  *ArpScanner
	synScanner  *SynScanner
	results     chan *ScanResult
	errorChan   chan error
	scanning    bool
	scanningMux *sync.RWMutex
	deviceMux   *sync.RWMutex
	debug       logger.DebugLogger
}

func NewFullScanner(
	netInfo network.Network,
	targets,
	ports []string,
	listenPort uint16,
	options ...ScannerOption,
) *FullScanner {
	ctx, cancel := context.WithCancel(context.Background())

	arpScanner := NewArpScanner(
		targets,
		netInfo,
	)

	synScanner := NewSynScanner(
		[]*ArpScanResult{},
		netInfo,
		ports,
		listenPort,
	)

	scanner := &FullScanner{
		ctx:         ctx,
		cancel:      cancel,
		netInfo:     netInfo,
		targets:     targets,
		listenPort:  listenPort,
		ports:       ports,
		devices:     []*ArpScanResult{},
		arpScanner:  arpScanner,
		synScanner:  synScanner,
		results:     make(chan *ScanResult),
		errorChan:   make(chan error),
		scanning:    false,
		scanningMux: &sync.RWMutex{},
		deviceMux:   &sync.RWMutex{},
		debug:       logger.NewDebugLogger(),
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *FullScanner) Results() chan *ScanResult {
	return s.results
}

func (s *FullScanner) Scan() error {
	s.scanningMux.RLock()
	scanning := s.scanning
	s.scanningMux.RUnlock()

	if scanning {
		return nil
	}

	s.scanningMux.Lock()
	s.scanning = true
	s.scanningMux.Unlock()

	defer s.reset()

	go func() {
		if err := s.arpScanner.Scan(); err != nil {
			s.errorChan <- err
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return nil
		case r := <-s.arpScanner.Results():
			switch r.Type {
			case ARPResult:
				go s.handleArpResult(r.Payload.(*ArpScanResult))
			case ARPDone:
				go s.handleArpDone()
			}
		case r := <-s.synScanner.Results():
			switch r.Type {
			case SYNResult:
				go func() {
					s.results <- r
				}()
			case SYNDone:
				go func() {
					s.results <- r
				}()
				return nil
			default:
				return fmt.Errorf("unknown result type: %s", r.Type)
			}
		case err := <-s.errorChan:
			return err
		}
	}
}

func (s *FullScanner) Stop() {
	s.cancel()

	if s.arpScanner != nil {
		s.arpScanner.Stop()
	}
	if s.synScanner != nil {
		s.synScanner.Stop()
	}
	s.debug.Info().Msg("all scanners stopped")
}

func (s *FullScanner) SetTiming(d time.Duration) {
	s.arpScanner.SetTiming(d)
	s.synScanner.SetTiming(d)
}

func (s *FullScanner) SetRequestNotifications(c chan *Request) {
	s.arpScanner.SetRequestNotifications(c)
	s.synScanner.SetRequestNotifications(c)
}

func (s *FullScanner) SetIdleTimeout(d time.Duration) {
	s.arpScanner.SetIdleTimeout(d)
	s.synScanner.SetIdleTimeout(d)
}

func (s *FullScanner) IncludeVendorInfo(repo oui.VendorRepo) {
	s.arpScanner.IncludeVendorInfo(repo)
	s.synScanner.IncludeVendorInfo(repo)
}

func (s *FullScanner) SetPacketCapture(cap PacketCapture) {
	s.arpScanner.SetPacketCapture(cap)
	s.synScanner.SetPacketCapture(cap)
}

func (s *FullScanner) handleArpDone() {
	s.deviceMux.RLock()
	defer s.deviceMux.RUnlock()

	go func() {
		s.results <- &ScanResult{
			Type: ARPDone,
		}
	}()

	s.synScanner.SetTargets(s.devices)

	go func() {
		if err := s.synScanner.Scan(); err != nil {
			s.errorChan <- err
		}
	}()
}

func (s *FullScanner) handleArpResult(result *ArpScanResult) {
	s.deviceMux.Lock()
	defer s.deviceMux.Unlock()

	go func() {
		s.results <- &ScanResult{
			Type:    ARPResult,
			Payload: result,
		}
	}()

	if !util.SliceIncludesFunc(s.devices, func(d *ArpScanResult, i int) bool {
		return d.IP.Equal(result.IP)
	}) {
		s.devices = append(s.devices, &ArpScanResult{
			IP:  result.IP,
			MAC: result.MAC,
		})

		slices.SortFunc(s.devices, func(d1, d2 *ArpScanResult) int {
			return bytes.Compare(d1.IP, d2.IP)
		})
	}

}

func (s *FullScanner) reset() {
	s.deviceMux.Lock()
	s.devices = []*ArpScanResult{}
	s.deviceMux.Unlock()

	s.scanningMux.Lock()
	s.scanning = false
	s.scanningMux.Unlock()

	if s.ctx.Err() != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.ctx = ctx
		s.cancel = cancel
	}
}
