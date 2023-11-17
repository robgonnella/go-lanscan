// SPDX-License-Identifier: GPL-3.0-or-later

package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jackpal/gateway"
)

func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// private helpers
func getIPNetByIP(ip net.IP) (*net.Interface, *net.IPNet, error) {
	interfaces, err := net.Interfaces()

	if err != nil {
		return nil, nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()

		if err != nil {
			continue
		}

		for _, addr := range addrs {
			_, ipnet, err := net.ParseCIDR(addr.String())

			if err != nil {
				continue
			}

			if ipnet.Contains(ip) {
				return &iface, ipnet, nil
			}
		}
	}

	return nil, nil, errors.New("failed to find IPNet")
}

func getDefaultNetworkInfo() (*networkInfo, error) {
	hostname, err := os.Hostname()

	if err != nil {
		return nil, err
	}

	gw, err := gateway.DiscoverGateway()

	if err != nil {
		return nil, err
	}

	// udp doesn't make a full connection and will find the default ip
	// that traffic will use if say 2 are configured (wired and wireless)
	conn, err := net.Dial("udp", gw.String()+":80")

	if err != nil {
		return nil, err
	}

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	foundIP := net.ParseIP(localAddr.IP.String())

	iface, ipnet, err := getIPNetByIP(foundIP)

	if err != nil {
		return nil, err
	}

	size, _ := ipnet.Mask.Size()

	ipCidr := fmt.Sprintf("%s/%d", foundIP.String(), size)

	ip, ipnet, err := net.ParseCIDR(ipCidr)

	if err != nil {
		return nil, err
	}

	firstCidrIP := ""

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); IncrementIP(ip) {
		if !strings.HasSuffix(ip.String(), ".0") {
			firstCidrIP = ip.String()
			break
		}
	}

	cidr := fmt.Sprintf("%s/%d", firstCidrIP, size)

	return &networkInfo{
		hostname: hostname,
		gateway:  gw,
		userIP:   foundIP,
		ipnet:    ipnet,
		iface:    iface,
		cidr:     cidr,
	}, nil
}

func getNetworkInfoFromInterfaceName(interfaceName string) (*networkInfo, error) {
	hostname, err := os.Hostname()

	if err != nil {
		return nil, err
	}

	gw, err := gateway.DiscoverGateway()

	if err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(interfaceName)

	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()

	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, errors.New("invalid interface - no address associated with interface")
	}

	cidr := ""

	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
			cidr = ip.String()
		}
	}

	userIP, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}

	size, _ := ipnet.Mask.Size()

	firstCidrIP := ""

	for ip := userIP.Mask(ipnet.Mask); ipnet.Contains(ip); IncrementIP(ip) {
		if !strings.HasSuffix(ip.String(), ".0") {
			firstCidrIP = ip.String()
			break
		}
	}

	cidr = fmt.Sprintf("%s/%d", firstCidrIP, size)

	return &networkInfo{
		hostname: hostname,
		gateway:  gw,
		userIP:   userIP,
		ipnet:    ipnet,
		iface:    iface,
		cidr:     cidr,
	}, nil
}
