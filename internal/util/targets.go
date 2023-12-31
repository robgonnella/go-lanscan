// SPDX-License-Identifier: GPL-3.0-or-later

package util

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/robgonnella/go-lanscan/pkg/network"
)

var cidrSuffix = regexp.MustCompile(`\/\d{1,2}$`)

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

	// nolint:errcheck
	LoopNetIPHosts(ipnet, func(ip net.IP) error {
		total++
		return nil
	})

	return total
}

// LoopTargets helper to prevent storing entire target list in memory
func LoopTargets(targets []string, f func(target net.IP) error) error {
	for _, t := range targets {
		if cidrSuffix.MatchString(t) {
			_, ipnet, err := net.ParseCIDR(t)

			if err != nil {
				return err
			}

			if err := LoopNetIPHosts(ipnet, f); err != nil {
				return err
			}
		} else {
			parts := strings.Split(t, "-")

			if len(parts) > 1 {
				start := net.ParseIP(parts[0])
				end := net.ParseIP(parts[1])
				// increment end by 1 to include it in loop
				network.IncrementIP(end)

				for ; !start.Equal(end); network.IncrementIP(start) {
					if err := f(start); err != nil {
						return err
					}
				}
			} else {
				if err := f(net.ParseIP(t)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// TotalTargets returns count of targets - helper to prevent storing entire
// target list in memory
func TotalTargets(targets []string) int {
	total := 0

	// nolint:errcheck
	LoopTargets(targets, func(ip net.IP) error {
		total++
		return nil
	})

	return total
}

// TargetsHas helper to determine if targets list includes a specific net.IP
func TargetsHas(targets []string, t net.IP) bool {
	has := false

	// nolint:errcheck
	LoopTargets(targets, func(v net.IP) error {
		if v.Equal(t) {
			has = true
		}

		return nil
	})

	return has
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

	// nolint:errcheck
	LoopPorts(ports, func(p uint16) error {
		total++
		return nil
	})

	return total
}
