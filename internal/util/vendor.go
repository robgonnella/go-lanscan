// SPDX-License-Identifier: GPL-3.0-or-later

package util

import (
	"io"
	"net/http"
	"os"
	"path"
)

func GetDefaultOuiTxtPath() (*string, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	dir := path.Join(home, ".config", "go-lanscan")

	if err := os.MkdirAll(dir, 0751); err != nil {
		return nil, err
	}

	ouiTxt := path.Join(dir, "oui.txt")

	return &ouiTxt, nil
}

func UpdateStaticVendors(ouiTxt string) error {
	resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")

	if err != nil {
		return err
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	file, err := os.OpenFile(ouiTxt, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		return err
	}

	defer file.Close()

	_, err = file.Write(data)

	return err
}
