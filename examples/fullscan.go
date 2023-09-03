// SYN Scanning example
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
	synResults := make(chan *scanner.SynScanResult)
	synDone := make(chan bool)
	listenPort := uint16(54321)

	scanner, err := scanner.NewFullScanner(
		netInfo,
		targets,
		ports,
		listenPort,
		synResults,
		synDone,
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
		case result, ok := <-synResults:
			if !ok {
				continue
			}
			fmt.Printf("syn scan result: %+v\n", result)
		case _, ok := <-synDone:
			if !ok {
				return
			}
			fmt.Println("syn scanning complete")
			return
		}
	}
}
