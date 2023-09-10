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
	"github.com/google/gopacket/pcap"
	"github.com/thediveo/netdb"

	"github.com/robgonnella/go-lanscan/network"
	"github.com/robgonnella/go-lanscan/util"
)

type SynScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	networkInfo      *network.NetworkInfo
	targets          []*ArpScanResult
	ports            []string
	listenPort       uint16
	handle           *pcap.Handle
	resultChan       chan *SynScanResult
	doneChan         chan bool
	notificationCB   func(a *Request)
	lastPacketTime   time.Time
	scanning         bool
	requestsComplete bool
	idleTimeout      time.Duration
	mux              sync.RWMutex
}

func NewSynScanner(
	targets []*ArpScanResult,
	networkInfo *network.NetworkInfo,
	ports []string,
	listenPort uint16,
	resultChan chan *SynScanResult,
	doneChan chan bool,
	options ...ScannerOption,
) *SynScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &SynScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		networkInfo:      networkInfo,
		ports:            ports,
		listenPort:       listenPort,
		resultChan:       resultChan,
		doneChan:         doneChan,
		lastPacketTime:   time.Time{},
		idleTimeout:      time.Second * 5,
		scanning:         false,
		requestsComplete: false,
		mux:              sync.RWMutex{},
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *SynScanner) Scan() error {
	if s.scanning {
		return nil
	}

	handle, err := pcap.OpenLive(
		s.networkInfo.Interface.Name,
		65536,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return err
	}

	expr := fmt.Sprintf("dst port %d", s.listenPort)

	handle.SetBPFFilter(expr)

	s.handle = handle

	s.scanning = true

	go s.readPackets()

	for _, target := range s.targets {
		err := util.LoopPorts(s.ports, func(port uint16) error {
			if err := s.writePacketData(target, port); err != nil {
				return err
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	s.requestsComplete = true

	return nil
}

func (s *SynScanner) Stop() {
	s.cancel()
	if s.handle != nil {
		s.handle.Close()
	}
	s.lastPacketTime = time.Time{}
	s.scanning = false
	s.requestsComplete = false
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *SynScanner) SetRequestNotifications(cb func(a *Request)) {
	s.notificationCB = cb
}

func (s *SynScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

func (s *SynScanner) IncludeVendorInfo(value bool) {
	// nothing to do
}

func (s *SynScanner) readPackets() {
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packetSource.NoCopy = true
	start := time.Now()

	for {
		select {
		case <-s.ctx.Done():
			s.Stop()
			return
		case packet := <-packetSource.Packets():
			s.handlePacket(packet)
		default:
			s.mux.RLock()
			packetTime := s.lastPacketTime
			s.mux.RUnlock()

			if s.requestsComplete && !packetTime.IsZero() && time.Since(packetTime) >= s.idleTimeout {
				s.Stop()
				s.doneChan <- true
				return
			}

			if s.requestsComplete && packetTime.IsZero() && time.Since(start) >= s.idleTimeout {
				s.Stop()
				s.doneChan <- true
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

	s.mux.Lock()
	s.lastPacketTime = time.Now()
	s.mux.Unlock()

	if tcp.SYN && tcp.ACK {
		serviceName := ""

		service := netdb.ServiceByPort(int(tcp.SrcPort), "")

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
			s.resultChan <- r
		}(result)
	}
}

func (s *SynScanner) writePacketData(target *ArpScanResult, port uint16) error {
	// open a new handle each time so we don't hit a buffer overflow error
	handle, err := pcap.OpenLive(
		s.networkInfo.Interface.Name,
		65536,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return err
	}

	defer handle.Close()

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC:       s.networkInfo.Interface.HardwareAddr,
		DstMAC:       target.MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		SrcIP:    s.networkInfo.UserIP.To4(),
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

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip4, &tcp); err != nil {
		return err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
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
