// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

type FullScanner struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	targets             []string
	ports               []string
	listenPort          uint16
	netInfo             network.Network
	options             []ScannerOption
	devices             []*ArpScanResult
	arpScanner          *ArpScanner
	synScanner          *SynScanner
	internalScanResults chan *ScanResult
	consumerResults     chan *ScanResult
	errorChan           chan error
	scanning            bool
	scanningMux         *sync.RWMutex
	deviceMux           *sync.RWMutex
}

func NewFullScanner(
	netInfo network.Network,
	targets,
	ports []string,
	listenPort uint16,
	results chan *ScanResult,
	options ...ScannerOption,
) *FullScanner {
	ctx, cancel := context.WithCancel(context.Background())

	internalScanResults := make(chan *ScanResult)

	arpScanner := NewArpScanner(
		targets,
		netInfo,
		internalScanResults,
	)

	scanner := &FullScanner{
		ctx:                 ctx,
		cancel:              cancel,
		netInfo:             netInfo,
		targets:             targets,
		listenPort:          listenPort,
		ports:               ports,
		devices:             []*ArpScanResult{},
		consumerResults:     results,
		arpScanner:          arpScanner,
		synScanner:          nil,
		internalScanResults: internalScanResults,
		errorChan:           make(chan error),
		options:             options,
		scanning:            false,
		scanningMux:         &sync.RWMutex{},
		deviceMux:           &sync.RWMutex{},
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
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
		case r := <-s.internalScanResults:
			switch r.Type {
			case ARPResult:
				go s.handleArpResult(r.Payload.(*ArpScanResult))
			case ARPDone:
				go s.handleArpDone()
			case SYNResult:
				go func() {
					s.consumerResults <- r
				}()
			case SYNDone:
				go func() {
					s.consumerResults <- r
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
}

func (s *FullScanner) SetRequestNotifications(cb func(req *Request)) {
	s.arpScanner.SetRequestNotifications(cb)
	s.options = append(s.options, WithRequestNotifications(cb))
}

func (s *FullScanner) SetIdleTimeout(d time.Duration) {
	s.arpScanner.SetIdleTimeout(d)
	s.options = append(s.options, WithIdleTimeout(d))
}

func (s *FullScanner) IncludeVendorInfo(repo oui.VendorRepo) {
	s.arpScanner.IncludeVendorInfo(repo)
	s.options = append(s.options, WithVendorInfo(repo))
}

func (s *FullScanner) SetAccuracy(accuracy Accuracy) {
	s.arpScanner.SetAccuracy(accuracy)
	s.options = append(s.options, WithAccuracy(accuracy))
}

func (s *FullScanner) SetPacketCapture(cap PacketCapture) {
	s.arpScanner.SetPacketCapture(cap)
	s.options = append(s.options, WithPacketCapture(cap))
}

func (s *FullScanner) handleArpDone() {
	s.deviceMux.RLock()
	defer s.deviceMux.RUnlock()

	go func() {
		s.consumerResults <- &ScanResult{
			Type: ARPDone,
		}
	}()

	synScanner := NewSynScanner(
		s.devices,
		s.netInfo,
		s.ports,
		s.listenPort,
		s.internalScanResults,
		s.options...,
	)

	go func() {
		if err := synScanner.Scan(); err != nil {
			s.errorChan <- err
		}
	}()
}

func (s *FullScanner) handleArpResult(result *ArpScanResult) {
	s.deviceMux.Lock()
	defer s.deviceMux.Unlock()

	go func() {
		s.consumerResults <- &ScanResult{
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
