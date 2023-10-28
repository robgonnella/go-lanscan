// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"github.com/robgonnella/go-lanscan/internal/cli"
	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/logger"
)

func main() {
	log := logger.New()

	runner := core.New()

	cmd, err := cli.Root(runner)

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize cli")
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("command encountered an error")
	}
}
