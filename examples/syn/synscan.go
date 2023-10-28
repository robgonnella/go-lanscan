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
	netInfo, err := network.GetNetworkInfo()

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
	synResults := make(chan *scanner.SynScanResult)
	synDone := make(chan bool)
	listenPort := uint16(54321)

	synScanner := scanner.NewSynScanner(
		targets,
		netInfo,
		ports,
		listenPort,
		synResults,
		synDone,
		scanner.WithIdleTimeout(time.Second*5),
	)

	go func() {
		if err := synScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for {
		select {
		case result := <-synResults:
			fmt.Printf("syn scan result: %+v\n", result)
		case <-synDone:
			fmt.Println("syn scanning complete")
			return
		}
	}
}