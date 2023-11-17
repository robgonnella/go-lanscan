// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"github.com/robgonnella/go-lanscan/internal/cli"
	"github.com/robgonnella/go-lanscan/internal/core"
	"github.com/robgonnella/go-lanscan/internal/logger"
	"github.com/robgonnella/go-lanscan/pkg/network"
	"github.com/robgonnella/go-lanscan/pkg/oui"
)

func main() {
	log := logger.New()

	userNet, err := network.NewDefaultNetwork()

	if err != nil {
		log.Fatal().Err(err).Msg("failed to find default network")
	}

	vendorRepo, err := oui.GetDefaultVendorRepo()

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize vendor repo")
	}

	runner := core.New()

	cmd, err := cli.Root(runner, userNet, vendorRepo)

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize cli")
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("command encountered an error")
	}
}
