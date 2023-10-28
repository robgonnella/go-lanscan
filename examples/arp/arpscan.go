// SPDX-License-Identifier: GPL-3.0-or-later

// ARP Scanning example
package main

import (
	"fmt"
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

	// Empty targets will default to scanning interface cidr. If you add something
	// to the targets list it will ignore the interface cidr and only scan
	// the specified targets.
	targets := []string{}
	arpResults := make(chan *scanner.ArpScanResult)
	arpDone := make(chan bool)
	idleTimeout := 5

	arpScanner := scanner.NewArpScanner(
		targets,
		netInfo,
		arpResults,
		arpDone,
		scanner.WithIdleTimeout(time.Second*time.Duration(idleTimeout)),
	)

	go func() {
		if err := arpScanner.Scan(); err != nil {
			panic(err)
		}
	}()

	for {
		select {
		case result := <-arpResults:
			fmt.Printf("arp scan result: %+v\n", result)
		case <-arpDone:
			fmt.Println("arp scanning complete")
			return
		}
	}
}
