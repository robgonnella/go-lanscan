// SPDX-License-Identifier: GPL-3.0-or-later

package core

import "github.com/robgonnella/go-lanscan/pkg/network"

//go:generate mockgen -destination=../mock/core/core.go -package=mock_core . Runner

type Runner interface {
	Initialize(
		accuracy string,
		targets []string,
		netInfo *network.NetworkInfo,
		ports []string,
		listenPort uint16,
		idleTimeoutSeconds int,
		noProgress bool,
		printJson bool,
		vendorInfo bool,
		arpOnly bool,
	)
	Run() error
}
