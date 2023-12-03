// SPDX-License-Identifier: GPL-3.0-or-later

// SYN Scanning example
package main

import (
	"fmt"
	"net"
	"time"

	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
)

func main() {
	// Find default interface info
	// i.e. Interface, IPNet, IP
	userNet, err := network.NewDefaultNetwork()

	if err != nil {
		panic(err)
	}

	mac1, err := net.ParseMAC("00:00:00:00:00:00")

	if err != nil {
		panic(err)
	}

	targets := []*scanner.ArpScanResult{
		{
			IP:  net.ParseIP("192.168.1.2"),
			MAC: mac1,
		},
	}

	ports := []string{"22", "111", "2000-4000"}
	listenPort := uint16(54321)

	synScanner := scanner.NewSynScanner(
		targets,
		userNet,
		ports,
		listenPort,
		scanner.WithIdleTimeout(time.Second*5),
	)

	go func() {
		if err := synScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for result := range synScanner.Results() {
		switch result.Type {
		case scanner.SYNResult:
			fmt.Printf("syn scan result: %+v\n", result.Payload.(*scanner.SynScanResult))
		case scanner.SYNDone:
			fmt.Println("syn scanning complete")
			return
		}
	}
}
