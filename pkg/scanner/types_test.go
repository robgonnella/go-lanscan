// SPDX-License-Identifier: GPL-3.0-or-later

package scanner_test

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/stretchr/testify/assert"
)

func TestArpScanResult(t *testing.T) {
	t.Run("serializes ArpScanResult", func(st *testing.T) {
		result := &scanner.ArpScanResult{
			IP:     net.ParseIP("172.17.1.1"),
			MAC:    net.HardwareAddr{},
			Vendor: "unknown",
		}

		serializable := result.Serializable()

		serialized, err := json.Marshal(serializable)

		assert.NoError(st, err)

		serializedMap := map[string]interface{}{}

		err = json.Unmarshal(serialized, &serializedMap)

		assert.NoError(st, err)

		assert.Equal(st, result.IP.String(), serializedMap["ip"])
		assert.Equal(st, result.MAC.String(), serializedMap["mac"])
		assert.Equal(st, result.Vendor, serializedMap["vendor"])
	})
}
