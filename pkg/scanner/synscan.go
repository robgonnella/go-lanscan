// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/thediveo/netdb"

	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

type SynScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	networkInfo      network.Network
	targets          []*ArpScanResult
	ports            []string
	listenPort       uint16
	cap              PacketCapture
	handle           PacketCaptureHandle
	resultChan       chan *ScanResult
	notificationCB   func(a *Request)
	scanning         bool
	lastPacketSentAt time.Time
	idleTimeout      time.Duration
	scanningMux      *sync.RWMutex
	packetSentAtMux  *sync.RWMutex
	serviceQueryMux  *sync.Mutex
	debug            logger.DebugLogger
}

func NewSynScanner(
	targets []*ArpScanResult,
	networkInfo network.Network,
	ports []string,
	listenPort uint16,
	options ...ScannerOption,
) *SynScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &SynScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		networkInfo:      networkInfo,
		cap:              &defaultPacketCapture{},
		ports:            ports,
		listenPort:       listenPort,
		resultChan:       make(chan *ScanResult),
		idleTimeout:      time.Second * 5,
		scanning:         false,
		lastPacketSentAt: time.Time{},
		scanningMux:      &sync.RWMutex{},
		packetSentAtMux:  &sync.RWMutex{},
		serviceQueryMux:  &sync.Mutex{},
		debug:            logger.NewDebugLogger(),
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *SynScanner) Results() chan *ScanResult {
	return s.resultChan
}

func (s *SynScanner) Scan() error {
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
		s.idleTimeout,
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

	limiter := time.NewTicker(defaultAccuracy)
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

	s.packetSentAtMux.Lock()
	defer s.packetSentAtMux.Unlock()
	s.lastPacketSentAt = time.Now()

	return nil
}

func (s *SynScanner) Stop() {
	s.cancel()

	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *SynScanner) SetRequestNotifications(cb func(a *Request)) {
	s.notificationCB = cb
}

func (s *SynScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

func (s *SynScanner) IncludeVendorInfo(repo oui.VendorRepo) {
	// nothing to do
}

func (s *SynScanner) SetPacketCapture(cap PacketCapture) {
	s.cap = cap
}

func (s *SynScanner) SetTargets(targets []*ArpScanResult) {
	s.targets = targets
}

func (s *SynScanner) readPackets() {
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions.NoCopy = true
	packetSource.DecodeOptions.Lazy = true

	defer s.reset()

	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			go s.handlePacket(packet)
		default:
			s.packetSentAtMux.RLock()
			packetSentAt := s.lastPacketSentAt
			s.packetSentAtMux.RUnlock()

			if !packetSentAt.IsZero() && time.Since(packetSentAt) >= s.idleTimeout {
				s.resultChan <- &ScanResult{
					Type: SYNDone,
				}
				return
			}
		}
	}
}

func (s *SynScanner) handlePacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()

	if netLayer == nil {
		return
	}

	srcIP := netLayer.NetworkFlow().Src().String()

	var targetIdx int

	isExpected := util.SliceIncludesFunc(s.targets, func(t *ArpScanResult, i int) bool {
		if t.IP.Equal(net.ParseIP(srcIP)) {
			targetIdx = i
			return true
		}

		return false
	})

	if !isExpected {
		return
	}

	target := s.targets[targetIdx]

	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	if tcp.DstPort != layers.TCPPort(s.listenPort) {
		return
	}

	if tcp.SYN && tcp.ACK {
		serviceName := ""

		s.serviceQueryMux.Lock()
		service := netdb.ServiceByPort(int(tcp.SrcPort), "")
		s.serviceQueryMux.Unlock()

		if service != nil {
			serviceName = service.Name
		}

		result := &SynScanResult{
			MAC:    target.MAC,
			IP:     target.IP,
			Status: StatusOnline,
			Port: Port{
				ID:      uint16(tcp.SrcPort),
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

	tcp.SetNetworkLayerForChecksum(&ip4)

	if err := s.cap.SerializeLayers(buf, opts, &eth, &ip4, &tcp); err != nil {
		return err
	}

	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	if s.notificationCB != nil {
		go s.notificationCB(&Request{
			Type: SynRequest,
			IP:   target.IP.String(),
			Port: port,
		})
	}

	return nil
}

func (s *SynScanner) reset() {
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
