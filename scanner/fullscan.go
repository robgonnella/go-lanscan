// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/robgonnella/go-lanscan/network"
	"github.com/robgonnella/go-lanscan/util"
)

type FullScanner struct {
	ctx               context.Context
	cancel            context.CancelFunc
	targets           []string
	ports             []string
	listenPort        uint16
	netInfo           *network.NetworkInfo
	options           []ScannerOption
	devices           []*ArpScanResult
	arpScanner        *ArpScanner
	internalArpResult chan *ArpScanResult
	internalArpDone   chan bool
	synScanner        *SynScanner
	internalSynResult chan *SynScanResult
	internalSynDone   chan bool
	consumerResults   chan *ScanResult
	errorChan         chan error
}

func NewFullScanner(
	netInfo *network.NetworkInfo,
	targets,
	ports []string,
	listenPort uint16,
	results chan *ScanResult,
	options ...ScannerOption,
) *FullScanner {
	internalArpResult := make(chan *ArpScanResult)
	internalArpDone := make(chan bool)

	arpScanner := NewArpScanner(
		targets,
		netInfo,
		internalArpResult,
		internalArpDone,
		options...,
	)

	ctx, cancel := context.WithCancel(context.Background())

	scanner := &FullScanner{
		ctx:               ctx,
		cancel:            cancel,
		netInfo:           netInfo,
		targets:           targets,
		listenPort:        listenPort,
		ports:             ports,
		devices:           []*ArpScanResult{},
		consumerResults:   results,
		arpScanner:        arpScanner,
		internalArpResult: internalArpResult,
		internalArpDone:   internalArpDone,
		synScanner:        nil,
		internalSynResult: make(chan *SynScanResult),
		internalSynDone:   make(chan bool),
		errorChan:         make(chan error),
		options:           options,
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
		case r := <-s.internalArpResult:
			go func() {
				s.consumerResults <- &ScanResult{
					Type:    ARPResult,
					Payload: r,
				}
			}()

			if !util.SliceIncludesFunc(s.devices, func(d *ArpScanResult, i int) bool {
				return d.IP.Equal(r.IP)
			}) {
				s.devices = append(s.devices, &ArpScanResult{
					IP:  r.IP,
					MAC: r.MAC,
				})

				slices.SortFunc(s.devices, func(d1, d2 *ArpScanResult) int {
					return bytes.Compare(d1.IP, d2.IP)
				})
			}
		case <-s.internalArpDone:
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
				s.internalSynResult,
				s.internalSynDone,
				s.options...,
			)

			go func() {
				if err := synScanner.Scan(); err != nil {
					s.errorChan <- err
				}
			}()
		case r := <-s.internalSynResult:
			go func() {
				s.consumerResults <- &ScanResult{
					Type:    SYNResult,
					Payload: r,
				}
			}()
		case <-s.internalSynDone:
			go func() {
				s.consumerResults <- &ScanResult{
					Type: SYNDone,
				}
			}()
			return nil
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
