// SPDX-License-Identifier: GPL-3.0-or-later

package oui

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	kloui "github.com/klauspost/oui"
)

type OUIVendorRepo struct {
	ouiTxt string
	db     kloui.StaticDB
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
	result := &VendorResult{
		Name: "unknown",
	}

	entry, err := r.db.Query(strings.ReplaceAll(mac.String(), ":", "-"))

	if errors.Is(err, kloui.ErrNotFound) {
		return result, nil
	}

	if err != nil {
		return nil, err
	}

	result.Name = entry.Manufacturer

	return result, nil
}

func (r *OUIVendorRepo) loadDatabase() error {
	db, err := kloui.OpenStaticFile(r.ouiTxt)

	if err != nil {
		return err
	}

	r.db = db

	return nil
}
