// SPDX-License-Identifier: GPL-3.0-or-later

package network

import "net"

//go:generate mockgen -destination=../../mock/network/network.go -package=mock_network . Network

// Network interface for accessing network properties
type Network interface {
	Hostname() string
	Interface() *net.Interface
	IPNet() *net.IPNet
	Gateway() net.IP
	UserIP() net.IP
	Cidr() string
}

type networkInfo struct {
	hostname string
	gateway  net.IP
	userIP   net.IP
	ipnet    *net.IPNet
	iface    *net.Interface
	cidr     string
}
