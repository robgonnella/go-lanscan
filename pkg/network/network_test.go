package network_test

import (
	"net"
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/stretchr/testify/assert"
)

func TestIncrementIP(t *testing.T) {
	t.Run("increments ip", func(st *testing.T) {
		ip := net.ParseIP("172.17.1.1")
		network.IncrementIP(ip)

		assert.Equal(st, "172.17.1.2", ip.String())
	})
}

func TestHostname(t *testing.T) {
	t.Run("gets default hostname", func(st *testing.T) {
		expectedHostname, err := os.Hostname()

		assert.NoError(st, err)

		hostName, err := network.Hostname()

		assert.NoError(st, err)

		assert.Equal(st, expectedHostname, *hostName)
	})
}

func TestGetNetworkInfoFromInterface(t *testing.T) {
	t.Run("gets network info with provided interface name", func(st *testing.T) {
		defaultNetInfo, err := network.GetNetworkInfo()

		assert.NoError(t, err)

		netInfo, err := network.GetNetworkInfoFromInterface(defaultNetInfo.Interface.Name)

		assert.NoError(st, err)

		assert.Equal(st, defaultNetInfo, netInfo)
	})

	t.Run("returns error for non-existent interface", func(st *testing.T) {
		netInfo, err := network.GetNetworkInfoFromInterface("nope")

		assert.Error(st, err)
		assert.Nil(st, netInfo)
	})

	t.Run("gets loopback interface", func(st *testing.T) {
		loopback := ""

		interfaces, err := net.Interfaces()

		assert.NoError(st, err)

		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
				loopback = iface.Name
				break
			}
		}

		if loopback == "" {
			st.FailNow()
		}

		netInfo, err := network.GetNetworkInfoFromInterface(loopback)

		assert.NoError(st, err)
		assert.NotNil(st, netInfo)
	})
}

func TestGetNetworkInfo(t *testing.T) {
	t.Run("gets default network info", func(st *testing.T) {
		netInfo, err := network.GetNetworkInfo()

		assert.NoError(st, err)
		assert.NotNil(st, netInfo)
	})
}
