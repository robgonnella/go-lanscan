// SPDX-License-Identifier: GPL-3.0-or-later

package network

import (
	"net"
)

// UserNetwork data structure for implementing Network interface
type UserNetwork struct {
	hostname string
	gateway  net.IP
	userIP   net.IP
	ipnet    *net.IPNet
	iface    *net.Interface
	cidr     string
}

// NewDefaultNetwork returns a new instance of UserNetwork
func NewDefaultNetwork() (*UserNetwork, error) {
	info, err := getDefaultNetworkInfo()

	if err != nil {
		return nil, err
	}

	return &UserNetwork{
		hostname: info.hostname,
		gateway:  info.gateway,
		userIP:   info.userIP,
		ipnet:    info.ipnet,
		iface:    info.iface,
		cidr:     info.cidr,
	}, nil
}

// NewNetworkFromInterfaceName returns a UserNetwork instance from the
// provided interface name
func NewNetworkFromInterfaceName(interfaceName string) (*UserNetwork, error) {
	info, err := getNetworkInfoFromInterfaceName(interfaceName)

	if err != nil {
		return nil, err
	}

	return &UserNetwork{
		hostname: info.hostname,
		gateway:  info.gateway,
		userIP:   info.userIP,
		ipnet:    info.ipnet,
		iface:    info.iface,
		cidr:     info.cidr,
	}, nil
}

// Hostname returns the hostname for this host
func (n *UserNetwork) Hostname() string {
	return n.hostname
}

// Gateway returns the default network gateway for this host
func (n *UserNetwork) Gateway() net.IP {
	return n.gateway
}

// UserIP returns the default IP address assigned to this network's interface
func (n *UserNetwork) UserIP() net.IP {
	return n.userIP
}

// IPNet returns the *net.IPNet associated with this network's interface
func (n *UserNetwork) IPNet() *net.IPNet {
	return n.ipnet
}

// Interface returns this network's interface
func (n *UserNetwork) Interface() *net.Interface {
	return n.iface
}

// Cidr returns the cidr block associated with this network's interface
func (n *UserNetwork) Cidr() string {
	return n.cidr
}
