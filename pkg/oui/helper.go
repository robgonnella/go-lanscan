// SPDX-License-Identifier: GPL-3.0-or-later

package oui

import (
	"os"
	"path"
)

// GetDefaultVendorRepo returns the default implementation of VendorRepo
// which uses github.com/klauspost/oui
func GetDefaultVendorRepo() (*OUIVendorRepo, error) {
	ouiTxt, err := GetDefaultOuiTxtPath()

	if err != nil {
		return nil, err
	}

	repo, err := NewOUIVendorRepo(*ouiTxt)

	if err != nil {
		return nil, err
	}

	return repo, nil
}

// GetDefaultOuiTxtPath returns the default path for the static oui.txt database
func GetDefaultOuiTxtPath() (*string, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	dir := path.Join(home, ".config", "go-lanscan")

	ouiTxt := path.Join(dir, "oui.txt")

	return &ouiTxt, nil
}
