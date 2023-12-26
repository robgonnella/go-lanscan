// SPDX-License-Identifier: GPL-3.0-or-later

package core

import "github.com/robgonnella/go-lanscan/pkg/scanner"

//go:generate mockgen -destination=../mock/core/core.go -package=mock_core . Runner

// Runner interface for performing network scanning
type Runner interface {
	Initialize(
		coreScanner scanner.Scanner,
		targetLen int,
		portLen int,
		noProgress bool,
		arpOnly bool,
		printJSON bool,
		outFile string,
	)
	Run() error
}
