// SPDX-License-Identifier: GPL-3.0-or-later

package network

import (
	"net"
)

type UserNetwork struct {
	hostname string
	gateway  net.IP
	userIP   net.IP
	ipnet    *net.IPNet
	iface    *net.Interface
	cidr     string
}

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

func (n *UserNetwork) Hostname() string {
	return n.hostname
}

func (n *UserNetwork) Gateway() net.IP {
	return n.gateway
}

func (n *UserNetwork) UserIP() net.IP {
	return n.userIP
}

func (n *UserNetwork) IPNet() *net.IPNet {
	return n.ipnet
}

func (n *UserNetwork) Interface() *net.Interface {
	return n.iface
}

func (n *UserNetwork) Cidr() string {
	return n.cidr
}
