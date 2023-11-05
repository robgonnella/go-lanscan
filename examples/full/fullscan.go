// SPDX-License-Identifier: GPL-3.0-or-later

// Full (ARP + SYN) Scanning example
package main

import (
	"fmt"

	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/robgonnella/go-lanscan/pkg/vendor"
)

func main() {
	// Find default interface info
	// i.e. Interface, IPNet, IP
	userNet, err := network.NewDefaultNetwork()

	if err != nil {
		panic(err)
	}

	vendorRepo, err := vendor.GetDefaultVendorRepo()

	if err != nil {
		panic(err)
	}

	targets := []string{}
	ports := []string{"22", "111", "2000-4000"}
	scanResults := make(chan *scanner.ScanResult)
	listenPort := uint16(54321)

	fullScanner := scanner.NewFullScanner(
		userNet,
		targets,
		ports,
		listenPort,
		scanResults,
		vendorRepo,
		scanner.WithVendorInfo(true),
	)

	go func() {
		if err := fullScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for res := range scanResults {
		switch res.Type {
		case scanner.ARPResult:
			fmt.Printf("arp scan result: %+v\n", res.Payload.(*scanner.ArpScanResult))
		case scanner.ARPDone:
			fmt.Println("arp scanning complete")
		case scanner.SYNResult:
			fmt.Printf("syn scan result: %+v\n", res.Payload.(*scanner.SynScanResult))
		case scanner.SYNDone:
			fmt.Println("syn scanning complete")
			return
		}
	}
}
