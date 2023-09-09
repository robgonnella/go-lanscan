// SPDX-License-Identifier: GPL-3.0-or-later

// Full (ARP + SYN) Scanning example
package main

import (
	"fmt"

	"github.com/robgonnella/go-lanscan/network"
	"github.com/robgonnella/go-lanscan/scanner"
)

func main() {
	// Find default interface info
	// i.e. Interface, IPNet, IP
	netInfo, err := network.GetNetworkInfo()

	if err != nil {
		panic(err)
	}

	targets := []string{}
	ports := []string{"22", "111", "2000-4000"}
	arpResults := make(chan *scanner.ArpScanResult)
	arpDone := make(chan bool)
	synResults := make(chan *scanner.SynScanResult)
	synDone := make(chan bool)
	listenPort := uint16(54321)
	vendorCB := func(v *scanner.VendorResult) {
		fmt.Printf("vendor result: %+v\n", v)
	}

	scanner, err := scanner.NewFullScanner(
		netInfo,
		targets,
		ports,
		listenPort,
		arpResults,
		arpDone,
		synResults,
		synDone,
		scanner.WithVendorInfo(vendorCB),
	)

	if err != nil {
		panic(err)
	}

	go func() {
		if err := scanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for {
		select {
		case result := <-arpResults:
			fmt.Printf("arp scan result: %+v\n", result)
		case <-arpDone:
			fmt.Println("arp scanning complete")
		case result := <-synResults:
			fmt.Printf("syn scan result: %+v\n", result)
		case <-synDone:
			fmt.Println("syn scanning complete")
			return
		}
	}
}
