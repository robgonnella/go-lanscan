// SPDX-License-Identifier: GPL-3.0-or-later

// ARP Scanning example
package main

import (
	"fmt"
	"time"

	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
)

func main() {
	// Find default interface info
	// i.e. Interface, IPNet, IP
	userNet, err := network.NewDefaultNetwork()

	if err != nil {
		panic(err)
	}

	vendorRepo, err := oui.GetDefaultVendorRepo()

	if err != nil {
		panic(err)
	}

	// Empty targets will default to scanning interface cidr. If you add something
	// to the targets list it will ignore the interface cidr and only scan
	// the specified targets.
	targets := []string{}
	results := make(chan *scanner.ScanResult)
	idleTimeout := 5

	arpScanner := scanner.NewArpScanner(
		targets,
		userNet,
		results,
		vendorRepo,
		scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeout)),
	)

	go func() {
		if err := arpScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for result := range results {
		switch result.Type {
		case scanner.ARPResult:
			fmt.Printf("arp scan result: %+v\n", result.Payload.(*scanner.ArpScanResult))
		case scanner.ARPDone:
			fmt.Println("arp scanning complete")
			return
		}
	}
}
