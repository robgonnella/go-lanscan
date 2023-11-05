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

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/vendor"
)

type ArpScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	targets          []string
	networkInfo      network.Network
	cap              PacketCapture
	handle           PacketCaptureHandle
	resultChan       chan *ScanResult
	notificationCB   func(a *Request)
	scanning         bool
	lastPacketSentAt time.Time
	idleTimeout      time.Duration
	includeVendor    bool
	accuracy         time.Duration
	vendorRepo       vendor.VendorRepo
	scanningMux      *sync.RWMutex
	packetSentAtMux  *sync.RWMutex
}

func NewArpScanner(
	targets []string,
	networkInfo network.Network,
	resultChan chan *ScanResult,
	vendorRepo vendor.VendorRepo,
	options ...ScannerOption,
) *ArpScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &ArpScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		cap:              &defaultPacketCapture{},
		networkInfo:      networkInfo,
		resultChan:       resultChan,
		idleTimeout:      time.Second * 5,
		scanning:         false,
		lastPacketSentAt: time.Time{},
		includeVendor:    false,
		accuracy:         time.Millisecond,
		vendorRepo:       vendorRepo,
		scanningMux:      &sync.RWMutex{},
		packetSentAtMux:  &sync.RWMutex{},
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *ArpScanner) Scan() error {
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
		s.idleTimeout,
	)

	if err != nil {
		s.scanning = false
		s.scanningMux.Unlock()
		return err
	}

	s.scanningMux.Unlock()
	s.handle = handle

	go s.readPackets()

	limiter := time.NewTicker(s.accuracy)
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
	s.scanningMux.Lock()
	s.scanning = false
	s.scanningMux.Unlock()
	s.packetSentAtMux.Lock()
	s.lastPacketSentAt = time.Time{}
	s.packetSentAtMux.Unlock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *ArpScanner) SetRequestNotifications(cb func(a *Request)) {
	s.notificationCB = cb
}

func (s *ArpScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

func (s *ArpScanner) IncludeVendorInfo(value bool) {
	s.includeVendor = value
}

func (s *ArpScanner) SetAccuracy(accuracy Accuracy) {
	s.accuracy = accuracy.Duration()
}

func (s *ArpScanner) SetPacketCapture(cap PacketCapture) {
	s.cap = cap
}

func (s *ArpScanner) readPackets() {
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions.NoCopy = true
	packetSource.DecodeOptions.Lazy = true

	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if arpLayer != nil {
				go s.handleARPLayer(arpLayer.(*layers.ARP))
			}
		default:
			s.packetSentAtMux.RLock()
			defer s.packetSentAtMux.RUnlock()

			if !s.lastPacketSentAt.IsZero() && time.Since(s.lastPacketSentAt) >= s.idleTimeout {
				s.Stop()
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

	if s.notificationCB != nil {
		go s.notificationCB(&Request{Type: ArpRequest, IP: ip.String()})
	}

	return nil
}

func (s *ArpScanner) processResult(ip net.IP, mac net.HardwareAddr) {
	arpResult := &ArpScanResult{
		IP:     ip,
		MAC:    mac,
		Vendor: "unknown",
	}

	if s.includeVendor {
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
