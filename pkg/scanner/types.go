// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

//go:generate mockgen -destination=../../mock/scanner/scanner.go -package=mock_scanner . Scanner,PacketCaptureHandle,PacketCapture

// RequestType represents a type of request packet sent to target
type RequestType string

const (
	// ArpRequest represents an ARP request
	ArpRequest RequestType = "ARP"
	// SynRequest represents a SYN request
	SynRequest RequestType = "SYN"
)

// Request represents a notification for a request packet sent to target host
type Request struct {
	Type RequestType
	IP   string
	Port uint16
}

// Scanner interface for scanning network devices
type Scanner interface {
	Scan() error
	Stop()
	Results() chan *ScanResult
	SetTiming(d time.Duration)
	SetRequestNotifications(c chan *Request)
	SetIdleTimeout(d time.Duration)
	IncludeVendorInfo(repo oui.VendorRepo)
	IncludeHostNames(v bool)
	SetPacketCapture(cap PacketCapture)
}

// PacketCaptureHandle interface for writing and reading packets to and from
// the wire
type PacketCaptureHandle interface {
	Close()
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	WritePacketData(data []byte) (err error)
	SetBPFFilter(expr string) (err error)
}

// PacketCapture interface for creating PacketCaptureHandles and
// serializing packet layers
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
	IP       net.IP
	MAC      net.HardwareAddr
	Hostname string
	Vendor   string
}

// Serializable returns a serializable version of ArpScanResult
func (r *ArpScanResult) Serializable() interface{} {
	return struct {
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		Hostname string `json:"hostname"`
		Vendor   string `json:"vendor"`
	}{
		IP:       r.IP.String(),
		MAC:      r.MAC.String(),
		Hostname: r.Hostname,
		Vendor:   r.Vendor,
	}
}

// ResultType represents a type of result sent through the result channel in
// each scanner implementation
type ResultType string

const (
	// ARPResult represents an ARP Result message
	ARPResult ResultType = "ARP"
	// ARPDone represents an ARP Done message
	ARPDone ResultType = "ARP_DONE"
	// SYNResult represents an SYN Result message
	SYNResult ResultType = "SYN"
	// SYNDone represents an SYN Done message
	SYNDone ResultType = "SYN_DONE"
)

// ScanResult represents a scanning result sent through the results channel
// in each in scanner implementation
type ScanResult struct {
	Type    ResultType
	Payload any
}
