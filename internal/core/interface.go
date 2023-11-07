// SPDX-License-Identifier: GPL-3.0-or-later

package core

import "github.com/robgonnella/go-lanscan/pkg/scanner"

//go:generate mockgen -destination=../mock/core/core.go -package=mock_core . Runner

type Runner interface {
	Initialize(
		coreScanner scanner.Scanner,
		scanResults chan *scanner.ScanResult,
		targetLen int,
		portLen int,
		noProgress bool,
		arpOnly bool,
		printJson bool,
	)
	Run() error
}
