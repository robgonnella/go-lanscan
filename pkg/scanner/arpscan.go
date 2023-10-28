// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/klauspost/oui"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/robgonnella/go-lanscan/pkg/network"
)

type ArpScanner struct {
	ctx              context.Context
	cancel           context.CancelFunc
	targets          []string
	networkInfo      *network.NetworkInfo
	handle           *pcap.Handle
	resultChan       chan *ScanResult
	notificationCB   func(a *Request)
	scanning         bool
	lastPacketSentAt time.Time
	idleTimeout      time.Duration
	includeVendor    bool
	accuracy         time.Duration
	ouiDb            *oui.StaticDB
}

func NewArpScanner(
	targets []string,
	networkInfo *network.NetworkInfo,
	resultChan chan *ScanResult,
	options ...ScannerOption,
) *ArpScanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &ArpScanner{
		ctx:              ctx,
		cancel:           cancel,
		targets:          targets,
		networkInfo:      networkInfo,
		resultChan:       resultChan,
		idleTimeout:      time.Second * 5,
		scanning:         false,
		lastPacketSentAt: time.Time{},
		includeVendor:    false,
		accuracy:         time.Millisecond,
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

	if err := s.initOuiDB(); err != nil {
		return err
	}

	// open a new handle each time so we don't hit buffer overflow error
	handle, err := pcap.OpenLive(
		s.networkInfo.Interface.Name,
		65536,
		true,
		s.idleTimeout,
	)

	if err != nil {
		return err
	}

	s.handle = handle

	s.scanning = true

	go s.readPackets()

	limiter := time.NewTicker(s.accuracy)
	defer limiter.Stop()

	if len(s.targets) == 0 {
		err = util.LoopNetIPHosts(s.networkInfo.IPNet, func(ip net.IP) error {
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

	s.lastPacketSentAt = time.Now()

	return err
}

func (s *ArpScanner) Stop() {
	s.cancel()
	if s.handle != nil {
		s.handle.Close()
	}
	s.scanning = false
	s.lastPacketSentAt = time.Time{}
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

func (s *ArpScanner) readPackets() {
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions.NoCopy = true
	packetSource.DecodeOptions.Lazy = true

	for {
		select {
		case <-s.ctx.Done():
			s.Stop()
			return
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if arpLayer != nil {
				go s.handleARPLayer(arpLayer.(*layers.ARP))
			}
		default:
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

	go s.processResult(ip, mac)
}

func (s *ArpScanner) writePacketData(ip net.IP) error {
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
		db := *s.ouiDb

		entry, err := db.Query(strings.ReplaceAll(mac.String(), ":", "-"))

		if err == nil && entry.Manufacturer != "" {
			arpResult.Vendor = entry.Manufacturer
		}
	}

	go func() {
		s.resultChan <- &ScanResult{
			Type:    ARPResult,
			Payload: arpResult,
		}
	}()
}

func (s *ArpScanner) initOuiDB() error {
	home, err := os.UserHomeDir()

	if err != nil {
		return err
	}

	dir := path.Join(home, ".config", "go-lanscan")
	ouiTxt := path.Join(dir, "oui.txt")

	_, err = os.Stat(ouiTxt)

	if errors.Is(err, os.ErrNotExist) && s.includeVendor && s.ouiDb == nil {
		resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")

		if err != nil {
			return err
		}

		data, err := io.ReadAll(resp.Body)

		if err != nil {
			return err
		}

		if err := os.MkdirAll(dir, 0751); err != nil {
			return err
		}

		file, err := os.OpenFile(ouiTxt, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

		if err != nil {
			return err
		}

		_, err = file.Write(data)

		if err != nil {
			file.Close()
			return err
		}

		file.Close()

		db, err := oui.OpenStaticFile(ouiTxt)

		if err != nil {
			return err
		}

		s.ouiDb = &db

		return nil
	} else {
		db, err := oui.OpenStaticFile(ouiTxt)

		if err != nil {
			return err
		}

		s.ouiDb = &db
	}

	return nil
}
