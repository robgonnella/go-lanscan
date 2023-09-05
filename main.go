// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"github.com/robgonnella/go-lanscan/command"
	"github.com/robgonnella/go-lanscan/logger"
)

func main() {
	log := logger.New()
	cmd, err := command.NewRoot()

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize cli")
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("command encountered an error")
	}
}
