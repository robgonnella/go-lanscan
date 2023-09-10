// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/robgonnella/go-lanscan/network"
	"github.com/robgonnella/go-lanscan/util"
)

type ArpScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	targets          []string
	networkInfo      *network.NetworkInfo
	handle           *pcap.Handle
	resultChan       chan *ArpScanResult
	doneChan         chan bool
	notificationCB   func(a *Request)
	scanning         bool
	requestsComplete bool
	lastPacketTime   time.Time
	idleTimeout      time.Duration
	semaphore        chan struct{}
	vendorCB         func(v *VendorResult)
	wg               *sync.WaitGroup
	mux              sync.RWMutex
}

func NewArpScanner(
	targets []string,
	networkInfo *network.NetworkInfo,
	resultChan chan *ArpScanResult,
	doneChan chan bool,
	options ...ScannerOption,
) *ArpScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &ArpScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		networkInfo:      networkInfo,
		resultChan:       resultChan,
		doneChan:         doneChan,
		lastPacketTime:   time.Time{},
		idleTimeout:      time.Second * 5,
		scanning:         false,
		requestsComplete: false,
		semaphore:        make(chan struct{}, 1),
		wg:               &sync.WaitGroup{},
		mux:              sync.RWMutex{},
	}

	for _, o := range options {
		o(scanner)
	}

	return scanner
}

func (s *ArpScanner) Scan() error {
	if s.scanning {
		return nil
	}

	// open a new handle each time so we don't hit buffer overflow error
	handle, err := pcap.OpenLive(
		s.networkInfo.Interface.Name,
		65536,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return err
	}

	s.handle = handle

	s.scanning = true

	go s.readPackets()

	if len(s.targets) == 0 {
		err = util.LoopNetIPHosts(s.networkInfo.IPNet, s.writePacketData)
	} else {
		err = util.LoopTargets(s.targets, s.writePacketData)
	}

	s.requestsComplete = true

	return err
}

func (s *ArpScanner) Stop() {
	s.cancel()
	if s.handle != nil {
		s.handle.Close()
	}
	s.lastPacketTime = time.Time{}
	s.scanning = false
	s.requestsComplete = false
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *ArpScanner) SetRequestNotifications(cb func(a *Request)) {
	s.notificationCB = cb
}

func (s *ArpScanner) SetIdleTimeout(duration time.Duration) {
	s.idleTimeout = duration
}

func (s *ArpScanner) SetVendorCB(cb func(v *VendorResult)) {
	s.vendorCB = cb
}

func (s *ArpScanner) readPackets() {
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packetSource.NoCopy = true
	start := time.Now()

	for {
		select {
		case <-s.ctx.Done():
			s.Stop()
			return
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if arpLayer != nil {
				s.handleARPLayer(arpLayer.(*layers.ARP))
			}
		default:
			s.mux.RLock()
			packetTime := s.lastPacketTime
			s.mux.RUnlock()

			if s.requestsComplete && !packetTime.IsZero() && time.Since(packetTime) >= s.idleTimeout {
				s.wg.Wait() // wait for requests to finish
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

func (s *ArpScanner) handleARPLayer(arp *layers.ARP) {
	if arp.Operation != layers.ARPReply {
		// not an arp reply
		return
	}

	if bytes.Equal([]byte(s.networkInfo.Interface.HardwareAddr), arp.SourceHwAddress) {
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
		if !s.networkInfo.IPNet.Contains(ip) {
			// not an arp response we care about
			return
		}
	}

	s.mux.Lock()
	s.lastPacketTime = time.Now()
	s.mux.Unlock()

	go s.processResult(ip, mac)
}

func (s *ArpScanner) writePacketData(ip net.IP) error {
	// open a new handle each time so we don't hit buffer overflow error
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

	eth := layers.Ethernet{
		SrcMAC:       s.networkInfo.Interface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.networkInfo.Interface.HardwareAddr),
		SourceProtAddress: []byte(s.networkInfo.UserIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ip.To4()),
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	if s.notificationCB != nil {
		go s.notificationCB(&Request{Type: ArpRequest, IP: ip.String()})
	}

	return nil
}

func (s *ArpScanner) processResult(ip net.IP, mac net.HardwareAddr) {
	s.resultChan <- &ArpScanResult{
		IP:  ip,
		MAC: mac,
	}

	if s.vendorCB != nil {
		s.wg.Add(1)

		s.semaphore <- struct{}{} // acquire lock

		wrapper := func() {
			vendor := &Vendor{Company: "Unknown"}

			url := fmt.Sprintf(
				"https://api.maclookup.app/v2/macs/%s",
				mac.String(),
			)

			response, _ := http.Get(url)

			json.NewDecoder(response.Body).Decode(&vendor)

			if vendor.Company == "" {
				vendor.Company = "Unknown"
			}

			go s.vendorCB(&VendorResult{
				MAC:    mac,
				Vendor: vendor.Company,
			})

			<-s.semaphore // release lock
			s.wg.Done()
		}

		time.AfterFunc(time.Second, wrapper)
	}
}
