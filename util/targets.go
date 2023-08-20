package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/robgonnella/go-lanscan/network"
)

// LoopNetIPHosts helper to prevent storing entire list in memory
func LoopNetIPHosts(ipnet *net.IPNet, f func(ip net.IP) error) error {
	for ip := net.ParseIP(ipnet.IP.String()); ipnet.Contains(ip); network.IncrementIP(ip) {
		if err := f(ip); err != nil {
			return err
		}
	}

	return nil
}

// IPHostTotal helper to get total number of hosts so we don't have to store
// the entire list in memory
func IPHostTotal(ipnet *net.IPNet) int {
	total := 0

	LoopNetIPHosts(ipnet, func(ip net.IP) error {
		total++
		return nil
	})

	return total
}

// LoopPorts helper to prevent storing entire list in memory
func LoopPorts(ports []string, f func(p uint16) error) error {
	for _, strPort := range ports {
		if strings.Contains(strPort, "-") {
			parts := strings.Split(strPort, "-")
			if len(parts) < 2 {
				return fmt.Errorf("invalid port: %s", strPort)
			}
			start, err := strconv.Atoi(parts[0])

			if err != nil {
				return fmt.Errorf("invalid port: %s", strPort)
			}

			end, err := strconv.Atoi(parts[1])

			if err != nil {
				return fmt.Errorf("invalid port: %s", strPort)
			}

			for i := start; i <= end; i++ {
				if err := f(uint16(i)); err != nil {
					return err
				}
			}
		} else {
			p, err := strconv.Atoi(strPort)
			if err != nil {
				return fmt.Errorf("invalid port: %s", strPort)
			}
			if err := f(uint16(p)); err != nil {
				return err
			}
		}
	}

	return nil
}

// PortTotal helper to get total number of ports so we don't have to store
// the entire list in memory
func PortTotal(ports []string) int {
	total := 0

	LoopPorts(ports, func(p uint16) error {
		total++
		return nil
	})

	return total
}
