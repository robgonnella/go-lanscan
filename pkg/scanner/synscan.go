// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/thediveo/netdb"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

// SynPacket represents a SYN packet response from one of the targeted hosts
type SynPacket struct {
	IP4 *layers.IPv4
	TCP *layers.TCP
}

// SynScanner implements the Scanner interface for SYN scanning
type SynScanner struct {
	cancel          chan struct{}
	networkInfo     network.Network
	targets         []*ArpScanResult
	ports           []string
	listenPort      uint16
	cap             PacketCapture
	handle          PacketCaptureHandle
	resultChan      chan *ScanResult
	requestNotifier chan *Request
	scanning        bool
	timing          time.Duration
	idleTimeout     time.Duration
	scanningMux     *sync.RWMutex
	serviceQueryMux *sync.Mutex
	debug           logger.DebugLogger
}

// NewSynScanner returns a new instance of SYNScanner
func NewSynScanner(
	targets []*ArpScanResult,
	networkInfo network.Network,
	ports []string,
	listenPort uint16,
	options ...Option,
) *SynScanner {
	scanner := &SynScanner{
		cancel:          make(chan struct{}),
		targets:         targets,
		networkInfo:     networkInfo,
		cap:             &defaultPacketCapture{},
		ports:           ports,
		listenPort:      listenPort,
		resultChan:      make(chan *ScanResult),
		timing:          defaultTiming,
		idleTimeout:     defaultIdleTimeout,
		scanning:        false,
		scanningMux:     &sync.RWMutex{},
		serviceQueryMux: &sync.Mutex{},
		debug:           logger.NewDebugLogger(),
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

// Results returns the channel for notifying when SYN responses are
// received from targeted hosts
func (s *SynScanner) Results() chan *ScanResult {
	return s.resultChan
}

// Scan implements SYN scanning
func (s *SynScanner) Scan() error {
	defer s.reset()

	fields := map[string]interface{}{
		"interface": s.networkInfo.Interface().Name,
		"cidr":      s.networkInfo.Cidr(),
		"targets":   s.targets,
		"ports":     s.ports,
	}

	s.debug.Info().Fields(fields).Msg("starting syn scan")

	s.scanningMux.RLock()
	scanning := s.scanning
	s.scanningMux.RUnlock()

	if scanning {
		return nil
	}

	s.scanningMux.Lock()
	s.scanning = true

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

	expr := fmt.Sprintf(
		"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn|tcp-ack && dst port %d",
		s.listenPort,
	)

	err = handle.SetBPFFilter(expr)

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

	for _, target := range s.targets {
		err := util.LoopPorts(s.ports, func(port uint16) error {
			// throttle calls to writePacketData to improve accuracy of results
			// the longer the time between calls the greater the accuracy.
			<-limiter.C
			if err := s.writePacketData(target, port); err != nil {
				return err
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	time.AfterFunc(s.idleTimeout, func() {
		go s.Stop()

		go func() {
			s.resultChan <- &ScanResult{
				Type: SYNDone,
			}
		}()
	})

	return nil
}

// Stop stops the scanner
func (s *SynScanner) Stop() {
	go func() {
		s.cancel <- struct{}{}
	}()

	if s.handle != nil {
		s.handle.Close()
	}
}

// SetTiming sets the timing duration for how long to wait in-between packet
// sends for SYN requests
func (s *SynScanner) SetTiming(d time.Duration) {
	s.timing = d
}

// SetRequestNotifications sets the channel for notifying when SYN requests
// are sent
func (s *SynScanner) SetRequestNotifications(c chan *Request) {
	s.requestNotifier = c
}

// SetIdleTimeout sets the idle timeout for this scanner
func (s *SynScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

// IncludeHostNames sets whether reverse dns look up is performed to find hostname
func (s *SynScanner) IncludeHostNames(v bool) {
	// nothing to do
}

// IncludeVendorInfo N/A for SYN scanner but here to satisfy Scanner interface
func (s *SynScanner) IncludeVendorInfo(_ oui.VendorRepo) {
	// nothing to do
}

// SetPacketCapture sets the packet capture implementation for this scanner
func (s *SynScanner) SetPacketCapture(cap PacketCapture) {
	s.cap = cap
}

// SetTargets sets the targets for SYN scanning
func (s *SynScanner) SetTargets(targets []*ArpScanResult) {
	s.targets = targets
}

func (s *SynScanner) readPackets() {
	for {
		select {
		case <-s.cancel:
			return
		default:
			var eth layers.Ethernet
			var ip4 layers.IPv4
			var tcp layers.TCP
			var payload gopacket.Payload

			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &payload)
			decoded := []gopacket.LayerType{}
			packetData, _, err := s.handle.ReadPacketData()

			if err != nil {
				s.debug.Error().Err(err).Msg("syn: read packet error")
				continue
			}

			err = parser.DecodeLayers(packetData, &decoded)

			if err != nil {
				s.debug.Error().Err(err).Msg("syn: decode packet error")
				continue
			}

			synPacket := &SynPacket{}

			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					synPacket.IP4 = &ip4
				case layers.LayerTypeTCP:
					synPacket.TCP = &tcp
				}
			}

			if synPacket.IP4 != nil && synPacket.TCP != nil {
				go s.handlePacket(synPacket)
			}
		}
	}
}

func (s *SynScanner) handlePacket(synPacket *SynPacket) {
	srcIP := synPacket.IP4.SrcIP

	var targetIdx int

	isExpected := util.SliceIncludesFunc(s.targets, func(t *ArpScanResult, i int) bool {
		if t.IP.Equal(srcIP) {
			targetIdx = i
			return true
		}

		return false
	})

	if !isExpected {
		return
	}

	target := s.targets[targetIdx]

	if synPacket.TCP.DstPort != layers.TCPPort(s.listenPort) {
		return
	}

	fields := map[string]interface{}{
		"ip":   target.IP,
		"port": synPacket.TCP.SrcPort.String(),
		"open": synPacket.TCP.SYN && synPacket.TCP.ACK,
	}

	s.debug.Info().Fields(fields).Msg("received response")

	if synPacket.TCP.SYN && synPacket.TCP.ACK {
		serviceName := ""

		s.serviceQueryMux.Lock()
		service := netdb.ServiceByPort(int(synPacket.TCP.SrcPort), "")
		s.serviceQueryMux.Unlock()

		if service != nil {
			serviceName = service.Name
		}

		result := &SynScanResult{
			MAC:    target.MAC,
			IP:     target.IP,
			Status: StatusOnline,
			Port: Port{
				ID:      uint16(synPacket.TCP.SrcPort),
				Service: serviceName,
				Status:  PortOpen,
			},
		}

		go func(r *SynScanResult) {
			s.resultChan <- &ScanResult{
				Type:    SYNResult,
				Payload: r,
			}
		}(result)
	}
}

func (s *SynScanner) writePacketData(target *ArpScanResult, port uint16) error {
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC:       s.networkInfo.Interface().HardwareAddr,
		DstMAC:       target.MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		SrcIP:    s.networkInfo.UserIP().To4(),
		DstIP:    target.IP.To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		SYN:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&ip4); err != nil {
		return err
	}

	if err := s.cap.SerializeLayers(buf, opts, &eth, &ip4, &tcp); err != nil {
		return err
	}

	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	if s.requestNotifier != nil {
		go func() {
			s.requestNotifier <- &Request{
				Type: SynRequest,
				IP:   target.IP.String(),
				Port: port,
			}
		}()
	}

	return nil
}

func (s *SynScanner) reset() {
	s.scanningMux.Lock()
	s.scanning = false
	s.scanningMux.Unlock()
}
