package network_test

import (
	"net"
	"os"
	"testing"

	"github.com/jackpal/gateway"
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

func TestDefaultUserNetwork(t *testing.T) {
	userNet, err := network.NewDefaultNetwork()

	assert.NoError(t, err)

	t.Run("gets hostname", func(st *testing.T) {
		expectedHostname, err := os.Hostname()

		assert.NoError(st, err)

		hostName, err := userNet.Hostname()

		assert.NoError(st, err)

		assert.Equal(st, expectedHostname, *hostName)
	})

	t.Run("gets gateway", func(st *testing.T) {
		expectedGw, err := gateway.DiscoverGateway()

		assert.NoError(st, err)

		gw := userNet.Gateway()

		assert.NoError(st, err)

		assert.Equal(st, expectedGw, gw)
	})

	t.Run("gets user ip", func(st *testing.T) {
		ip := userNet.UserIP()

		assert.NotNil(st, ip)
	})

	t.Run("gets interface", func(st *testing.T) {
		iface := userNet.Interface()

		assert.NotNil(st, iface)
	})

	t.Run("gets ipnet", func(st *testing.T) {
		ipnet := userNet.IPNet()

		assert.NotNil(st, ipnet)
	})

	t.Run("gets cidr", func(st *testing.T) {
		cidr := userNet.Cidr()

		assert.NotNil(st, cidr)
	})
}

func TestGetNetworkInfoFromInterface(t *testing.T) {
	t.Run("gets network info with provided interface name", func(st *testing.T) {
		defaultNetInfo, err := network.NewDefaultNetwork()

		assert.NoError(t, err)

		userNet, err := network.NewNetworkFromInterfaceName(defaultNetInfo.Interface().Name)

		assert.NoError(st, err)

		st.Run("gets hostname", func(st *testing.T) {
			expectedHostname, err := os.Hostname()

			assert.NoError(st, err)

			hostName, err := userNet.Hostname()

			assert.NoError(st, err)

			assert.Equal(st, expectedHostname, *hostName)
		})

		st.Run("gets gateway", func(st *testing.T) {
			expectedGw, err := gateway.DiscoverGateway()

			assert.NoError(st, err)

			gw := userNet.Gateway()

			assert.NoError(st, err)

			assert.Equal(st, expectedGw, gw)
		})

		st.Run("gets user ip", func(st *testing.T) {
			ip := userNet.UserIP()

			assert.NotNil(st, ip)
		})

		st.Run("gets interface", func(st *testing.T) {
			iface := userNet.Interface()

			assert.NotNil(st, iface)
		})

		st.Run("gets ipnet", func(st *testing.T) {
			ipnet := userNet.IPNet()

			assert.NotNil(st, ipnet)
		})

		st.Run("gets cidr", func(st *testing.T) {
			cidr := userNet.Cidr()

			assert.NotNil(st, cidr)
		})
	})

	t.Run("returns error for non-existent interface", func(st *testing.T) {
		netInfo, err := network.NewNetworkFromInterfaceName("nope")

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

		userNet, err := network.NewNetworkFromInterfaceName(loopback)

		assert.NoError(st, err)
		assert.NotNil(st, userNet)

		st.Run("gets hostname", func(st *testing.T) {
			expectedHostname, err := os.Hostname()

			assert.NoError(st, err)

			hostName, err := userNet.Hostname()

			assert.NoError(st, err)

			assert.Equal(st, expectedHostname, *hostName)
		})

		st.Run("gets gateway", func(st *testing.T) {
			expectedGw, err := gateway.DiscoverGateway()

			assert.NoError(st, err)

			gw := userNet.Gateway()

			assert.NoError(st, err)

			assert.Equal(st, expectedGw, gw)
		})

		st.Run("gets user ip", func(st *testing.T) {
			ip := userNet.UserIP()

			assert.NotNil(st, ip)
		})

		st.Run("gets interface", func(st *testing.T) {
			iface := userNet.Interface()

			assert.NotNil(st, iface)
		})

		st.Run("gets ipnet", func(st *testing.T) {
			ipnet := userNet.IPNet()

			assert.NotNil(st, ipnet)
		})

		st.Run("gets cidr", func(st *testing.T) {
			cidr := userNet.Cidr()

			assert.NotNil(st, cidr)
		})
	})
}
