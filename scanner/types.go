// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"net"
	"time"
)

//go:generate mockgen -destination=../mock/scanner/scanner.go -package=mock_scanner . Scanner

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
	SetRequestNotifications(cb func(a *Request))
	SetIdleTimeout(d time.Duration)
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
	ID      uint16
	Service string
	Status  PortStatus
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
	MAC net.HardwareAddr
	IP  net.IP
}

func (r *ArpScanResult) Serializable() interface{} {
	return struct {
		IP  string `json:"ip"`
		MAC string `json:"mac"`
	}{
		IP:  r.IP.String(),
		MAC: r.MAC.String(),
	}
}

type VendorResult struct {
	MAC    net.HardwareAddr
	Vendor string
}

type Vendor struct {
	Success   bool   `json:"success"`
	Found     bool   `json:"found"`
	Error     string `json:"error"`
	ErrorCode int    `json:"errorCode"`
	Company   string `json:"company"`
}
