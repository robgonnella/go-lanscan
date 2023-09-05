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
	ctx            context.Context
	cancel         context.CancelFunc
	targets        []string
	ports          []string
	listenPort     uint16
	netInfo        *network.NetworkInfo
	options        []ScannerOption
	devices        []*ArpScanResult
	resultChan     chan *SynScanResult
	done           chan bool
	arpScanner     *ArpScanner
	arpResult      chan *ArpScanResult
	arpDone        chan bool
	synScanner     *SynScanner
	synResult      chan *SynScanResult
	synDone        chan bool
	internalDone   chan bool
	errorChan      chan error
	idleTimeout    time.Duration
	notificationCB func(req *Request)
}

func NewFullScanner(
	netInfo *network.NetworkInfo,
	targets,
	ports []string,
	listenPort uint16,
	resultChan chan *SynScanResult,
	done chan bool,
	options ...ScannerOption,
) (*FullScanner, error) {
	arpResult := make(chan *ArpScanResult)
	arpDone := make(chan bool)

	arpScanner, err := NewArpScanner(
		targets,
		netInfo,
		arpResult,
		arpDone,
		options...,
	)

	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	scanner := &FullScanner{
		ctx:          ctx,
		cancel:       cancel,
		netInfo:      netInfo,
		targets:      targets,
		listenPort:   listenPort,
		ports:        ports,
		devices:      []*ArpScanResult{},
		resultChan:   resultChan,
		done:         done,
		arpScanner:   arpScanner,
		arpResult:    arpResult,
		arpDone:      arpDone,
		synScanner:   nil,
		synResult:    resultChan,
		synDone:      done,
		internalDone: make(chan bool),
		errorChan:    make(chan error),
		options:      options,
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner, nil
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
		case r, ok := <-s.arpResult:
			if !ok {
				continue
			}
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
		case _, ok := <-s.arpDone:
			if !ok {
				continue
			}

			synScanner, err := NewSynScanner(
				s.devices,
				s.netInfo,
				s.ports,
				s.listenPort,
				s.synResult,
				s.synDone,
				s.options...,
			)

			if err != nil {
				return err
			}

			go func() {
				if err := synScanner.Scan(); err != nil {
					s.errorChan <- err
				}
				s.internalDone <- true
			}()

		case _, ok := <-s.internalDone:
			if !ok {
				continue
			}

			return nil
		case err, ok := <-s.errorChan:
			if !ok {
				continue
			}

			return err
		}
	}
}

func (s *FullScanner) Stop() {
	s.cancel()
}

func (s *FullScanner) SetRequestNotifications(cb func(req *Request)) {
	s.notificationCB = cb
}

func (s *FullScanner) SetIdleTimeout(d time.Duration) {
	s.idleTimeout = d
}
