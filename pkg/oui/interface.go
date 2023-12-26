// SPDX-License-Identifier: GPL-3.0-or-later

package oui

import (
	"net"
)

//go:generate mockgen -destination=../../mock/oui/oui.go -package=mock_oui . VendorRepo

// VendorResult represents a vendor result when querying the vendor repo
type VendorResult struct {
	Name string
}

// VendorRepo interface for looking up vendor info by MAC address
type VendorRepo interface {
	UpdateVendors() error
	Query(mac net.HardwareAddr) (*VendorResult, error)
}
