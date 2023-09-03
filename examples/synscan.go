// SYN Scanning example
package main

import (
	"fmt"
	"net"
	"time"

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

	synScanner, err := scanner.NewSynScanner(
		targets,
		netInfo,
		ports,
		listenPort,
		synResults,
		synDone,
		scanner.WithSynIdleTimeout(time.Second*5),
	)

	if err != nil {
		panic(err)
	}

	go func() {
		if err := synScanner.Scan(); err != nil {
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
