// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
)

type FullScanner struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	targets             []string
	ports               []string
	listenPort          uint16
	netInfo             *network.NetworkInfo
	options             []ScannerOption
	devices             []*ArpScanResult
	arpScanner          *ArpScanner
	synScanner          *SynScanner
	internalScanResults chan *ScanResult
	consumerResults     chan *ScanResult
	errorChan           chan error
}

func NewFullScanner(
	netInfo *network.NetworkInfo,
	targets,
	ports []string,
	listenPort uint16,
	results chan *ScanResult,
	options ...ScannerOption,
) *FullScanner {
	internalScanResults := make(chan *ScanResult)

	arpScanner := NewArpScanner(
		targets,
		netInfo,
		internalScanResults,
		options...,
	)

	ctx, cancel := context.WithCancel(context.Background())

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
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *FullScanner) Scan() error {
	defer s.Stop()

	go func() {
		if err := s.arpScanner.Scan(); err != nil {
			s.errorChan <- err
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case r := <-s.internalScanResults:
			switch r.Type {
			case ARPResult:
				s.handleArpResult(r.Payload.(*ArpScanResult))
			case ARPDone:
				s.handleArpDone()
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
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *FullScanner) SetRequestNotifications(cb func(req *Request)) {
	s.arpScanner.SetRequestNotifications(cb)
	s.options = append(s.options, WithRequestNotifications(cb))
}

func (s *FullScanner) SetIdleTimeout(d time.Duration) {
	s.arpScanner.SetIdleTimeout(d)
	s.options = append(s.options, WithIdleTimeout(d))
}

func (s *FullScanner) IncludeVendorInfo(value bool) {
	s.arpScanner.IncludeVendorInfo(value)
	s.options = append(s.options, WithVendorInfo(value))
}

func (s *FullScanner) SetAccuracy(accuracy Accuracy) {
	s.arpScanner.SetAccuracy(accuracy)
	s.options = append(s.options, WithAccuracy(accuracy))
}

func (s *FullScanner) handleArpDone() {
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
