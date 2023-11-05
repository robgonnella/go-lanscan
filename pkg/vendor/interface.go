package vendor

import "net"

//go:generate mockgen -destination=../../mock/vendor/vendor.go -package=mock_vendor . VendorRepo

type VendorResult struct {
	Name string
}

type VendorRepo interface {
	Query(mac net.HardwareAddr) (*VendorResult, error)
}
