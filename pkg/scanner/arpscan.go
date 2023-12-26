// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

type ArpScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	targets          []string
	networkInfo      network.Network
	cap              PacketCapture
	handle           PacketCaptureHandle
	resultChan       chan *ScanResult
	requestNotifier  chan *Request
	scanning         bool
	lastPacketSentAt time.Time
	timing           time.Duration
	idleTimeout      time.Duration
	vendorRepo       oui.VendorRepo
	scanningMux      *sync.RWMutex
	packetSentAtMux  *sync.RWMutex
	debug            logger.DebugLogger
}

func NewArpScanner(
	targets []string,
	networkInfo network.Network,
	options ...ScannerOption,
) *ArpScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &ArpScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		cap:              &defaultPacketCapture{},
		networkInfo:      networkInfo,
		resultChan:       make(chan *ScanResult),
		timing:           defaultTiming,
		idleTimeout:      defaultIdleTimeout,
		scanning:         false,
		lastPacketSentAt: time.Time{},
		scanningMux:      &sync.RWMutex{},
		packetSentAtMux:  &sync.RWMutex{},
		debug:            logger.NewDebugLogger(),
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *ArpScanner) Results() chan *ScanResult {
	return s.resultChan
}

func (s *ArpScanner) Scan() error {
	fields := map[string]interface{}{
		"interface": s.networkInfo.Interface().Name,
		"cidr":      s.networkInfo.Cidr(),
		"targets":   s.targets,
	}
	s.debug.Info().Fields(fields).Msg("starting arp scan")

	s.scanningMux.RLock()
	scanning := s.scanning
	s.scanningMux.RUnlock()

	if scanning {
		return nil
	}

	s.scanningMux.Lock()
	s.scanning = true

	// open a new handle each time so we don't hit buffer overflow error
	handle, err := s.cap.OpenLive(
		s.networkInfo.Interface().Name,
		65536,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		s.scanning = false
		s.scanningMux.Unlock()
		return err
	}

	s.scanningMux.Unlock()
	s.handle = handle

	go s.readPackets()

	limiter := time.NewTicker(s.timing)
	defer limiter.Stop()

	if len(s.targets) == 0 {
		err = util.LoopNetIPHosts(s.networkInfo.IPNet(), func(ip net.IP) error {
			// throttle calls to writePacketData to improve accuracy of results
			// the longer the time between calls the greater the accuracy.
			<-limiter.C
			return s.writePacketData(ip)
		})
	} else {
		err = util.LoopTargets(s.targets, func(ip net.IP) error {
			// throttle calls to writePacketData to improve accuracy of results
			// the longer the time between calls the greater the accuracy.
			<-limiter.C
			return s.writePacketData(ip)
		})
	}

	s.packetSentAtMux.Lock()
	defer s.packetSentAtMux.Unlock()
	s.lastPacketSentAt = time.Now()

	return err
}

func (s *ArpScanner) Stop() {
	s.cancel()

	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *ArpScanner) SetTiming(d time.Duration) {
	s.timing = d
}

func (s *ArpScanner) SetRequestNotifications(c chan *Request) {
	s.requestNotifier = c
}

func (s *ArpScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

func (s *ArpScanner) IncludeVendorInfo(repo oui.VendorRepo) {
	s.vendorRepo = repo
	if err := s.vendorRepo.UpdateVendors(); err != nil {
		panic(err)
	}
}

func (s *ArpScanner) SetPacketCapture(cap PacketCapture) {
	s.cap = cap
}

func (s *ArpScanner) readPackets() {
	stopChan := make(chan struct{})

	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				var eth layers.Ethernet
				var arp layers.ARP
				var payload gopacket.Payload

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &payload)
				decoded := []gopacket.LayerType{}
				packetData, _, err := s.handle.ReadPacketData()

				if err != nil {
					s.debug.Error().Err(err).Msg("arp: error reading packet")
					continue
				}

				err = parser.DecodeLayers(packetData, &decoded)

				if err != nil {
					s.debug.Error().Err(err).Msg("arp: error decoding packet")
					continue
				}

			OUTER:
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeARP:
						go s.handleARPLayer(&arp)
						break OUTER
					}
				}
			}
		}
	}()

	defer func() {
		stopChan <- struct{}{}
		s.reset()
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.packetSentAtMux.RLock()
			packetSentAt := s.lastPacketSentAt
			s.packetSentAtMux.RUnlock()

			if !packetSentAt.IsZero() && time.Since(packetSentAt) >= s.idleTimeout {
				s.resultChan <- &ScanResult{
					Type: ARPDone,
				}
				return
			}
		}
	}
}

func (s *ArpScanner) handleARPLayer(arp *layers.ARP) {
	if arp.Operation != layers.ARPReply {
		// not an arp reply
		return
	}

	if bytes.Equal([]byte(s.networkInfo.Interface().HardwareAddr), arp.SourceHwAddress) {
		// This is a packet we sent
		return
	}

	ip := net.IP(arp.SourceProtAddress)
	mac := net.HardwareAddr(arp.SourceHwAddress)

	if len(s.targets) > 0 {
		if !util.TargetsHas(s.targets, ip) {
			// not an arp response we care about
			return
		}
	} else {
		if !s.networkInfo.IPNet().Contains(ip) {
			// not an arp response we care about
			return
		}
	}

	go s.processResult(ip, mac)
}

func (s *ArpScanner) writePacketData(ip net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       s.networkInfo.Interface().HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.networkInfo.Interface().HardwareAddr),
		SourceProtAddress: []byte(s.networkInfo.UserIP().To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ip.To4()),
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := s.cap.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	if s.requestNotifier != nil {
		go func() {
			s.requestNotifier <- &Request{Type: ArpRequest, IP: ip.String()}
		}()
	}

	return nil
}

func (s *ArpScanner) processResult(ip net.IP, mac net.HardwareAddr) {
	arpResult := &ArpScanResult{
		IP:     ip,
		MAC:    mac,
		Vendor: "unknown",
	}

	if s.vendorRepo != nil {
		vendor, err := s.vendorRepo.Query(mac)

		if err == nil {
			arpResult.Vendor = vendor.Name
		}
	}

	go func() {
		s.resultChan <- &ScanResult{
			Type:    ARPResult,
			Payload: arpResult,
		}
	}()
}

func (s *ArpScanner) reset() {
	s.scanningMux.Lock()
	s.scanning = false
	s.scanningMux.Unlock()

	s.packetSentAtMux.Lock()
	s.lastPacketSentAt = time.Time{}
	s.packetSentAtMux.Unlock()

	if s.ctx.Err() != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.ctx = ctx
		s.cancel = cancel
	}
}
