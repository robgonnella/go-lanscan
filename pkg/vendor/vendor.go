package vendor

import (
	"net"
	"strings"

	"github.com/klauspost/oui"
)

type OUIVendorRepo struct {
	db oui.StaticDB
}

func NewOUIVendorRepo(db oui.StaticDB) *OUIVendorRepo {
	return &OUIVendorRepo{db}
}

func (r *OUIVendorRepo) Query(mac net.HardwareAddr) (*VendorResult, error) {
	entry, err := r.db.Query(strings.ReplaceAll(mac.String(), ":", "-"))

	if err != nil {
		return nil, err
	}

	name := entry.Manufacturer

	if name == "" {
		name = "unknown"
	}

	return &VendorResult{
		Name: name,
	}, nil
}
