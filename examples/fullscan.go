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
	scanResults := make(chan *scanner.ScanResult)
	listenPort := uint16(54321)
	vendorCB := func(v *scanner.VendorResult) {
		fmt.Printf("vendor result: %+v\n", v)
	}

	fullScanner := scanner.NewFullScanner(
		netInfo,
		targets,
		ports,
		listenPort,
		scanResults,
		scanner.WithVendorInfo(vendorCB),
	)

	go func() {
		if err := fullScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for {
		select {
		case res := <-scanResults:
			switch res.Type {
			case scanner.ARPResult:
				fmt.Printf("arp scan result: %+v\n", res.Payload)
			case scanner.ARPDone:
				fmt.Println("arp scanning complete")
			case scanner.SYNResult:
				fmt.Printf("syn scan result: %+v\n", res.Payload)
			case scanner.SYNDone:
				fmt.Println("syn scanning complete")
				return
			}
		}
	}
}
