// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

//go:generate mockgen -destination=../../mock/scanner/scanner.go -package=mock_scanner . Scanner,PacketCaptureHandle,PacketCapture

type RequestType string

const (
	ArpRequest RequestType = "ARP"
	SynRequest RequestType = "SYN"
)

type Request struct {
	Type RequestType
	IP   string
	Port uint16
}

// Scanner interface for scanning a network for devices
type Scanner interface {
	Scan() error
	Stop()
	Results() chan *ScanResult
	SetRequestNotifications(cb func(a *Request))
	SetIdleTimeout(d time.Duration)
	IncludeVendorInfo(repo oui.VendorRepo)
	SetPacketCapture(cap PacketCapture)
}

type PacketCaptureHandle interface {
	Close()
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	WritePacketData(data []byte) (err error)
	SetBPFFilter(expr string) (err error)
}

type PacketCapture interface {
	OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle PacketCaptureHandle, _ error)
	SerializeLayers(w gopacket.SerializeBuffer, opts gopacket.SerializeOptions, layers ...gopacket.SerializableLayer) error
}

// Status represents possible server statues
type Status string

const (
	// StatusUnknown unknown status for server
	StatusUnknown Status = "unknown"
	// StatusOnline status if server is online
	StatusOnline Status = "online"
	// StatusOffline status if server is offline
	StatusOffline Status = "offline"
)

// PortStatus represents possible port statuses
type PortStatus string

const (
	// PortOpen status used when a port is marked open
	PortOpen PortStatus = "open"
	// PortClosed status used when a port is marked closed
	PortClosed PortStatus = "closed"
)

// Port data structure representing a server port
type Port struct {
	ID      uint16     `json:"id"`
	Service string     `json:"service"`
	Status  PortStatus `json:"status"`
}

// SynScanResult represents a single network device result from syn scan
type SynScanResult struct {
	MAC    net.HardwareAddr
	IP     net.IP
	Status Status
	Port   Port
}

// ArpScanResult represents a single network device result from arp scan
type ArpScanResult struct {
	IP     net.IP
	MAC    net.HardwareAddr
	Vendor string
}

func (r *ArpScanResult) Serializable() interface{} {
	return struct {
		IP     string `json:"ip"`
		MAC    string `json:"mac"`
		Vendor string `json:"vendor"`
	}{
		IP:     r.IP.String(),
		MAC:    r.MAC.String(),
		Vendor: r.Vendor,
	}
}

type ResultType string

const (
	ARPResult ResultType = "ARP"
	ARPDone   ResultType = "ARP_DONE"
	SYNResult ResultType = "SYN"
	SYNDone   ResultType = "SYN_DONE"
)

type ScanResult struct {
	Type    ResultType
	Payload any
}
