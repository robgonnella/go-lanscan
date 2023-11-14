// SPDX-License-Identifier: GPL-3.0-or-later

package vendor

import (
	"os"
	"path"
)

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

func GetDefaultOuiTxtPath() (*string, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	dir := path.Join(home, ".config", "go-lanscan")

	ouiTxt := path.Join(dir, "oui.txt")

	return &ouiTxt, nil
}
