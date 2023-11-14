package vendor

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/oui"
)

type OUIVendorRepo struct {
	ouiTxt string
	db     oui.StaticDB
}

func NewOUIVendorRepo(ouiTxt string) (*OUIVendorRepo, error) {
	repo := &OUIVendorRepo{ouiTxt: ouiTxt}

	if _, err := os.Stat(ouiTxt); errors.Is(err, os.ErrNotExist) {
		if err := repo.UpdateVendors(); err != nil {
			return nil, err
		}
	}

	return repo, nil
}

func (r *OUIVendorRepo) UpdateVendors() error {
	dir := filepath.Dir(r.ouiTxt)

	if err := os.MkdirAll(dir, 0751); err != nil {
		return err
	}

	resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")

	if err != nil {
		return err
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	file, err := os.OpenFile(r.ouiTxt, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		return err
	}

	defer file.Close()

	if _, err = file.Write(data); err != nil {
		return err
	}

	return r.loadDatabase()
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

func (r *OUIVendorRepo) loadDatabase() error {
	db, err := oui.OpenStaticFile(r.ouiTxt)

	if err != nil {
		return err
	}

	r.db = db

	return nil
}
