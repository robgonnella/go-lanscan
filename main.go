// SPDX-License-Identifier: GPL-3.0-or-later
//go:generate go run internal/scripts/gen-version.go

package main

import (
	"github.com/robgonnella/go-lanscan/internal/cli"
	"github.com/robgonnella/go-lanscan/internal/logger"
)

func main() {
	log := logger.New()
	cmd, err := cli.NewRoot()

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize cli")
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("command encountered an error")
	}
}
