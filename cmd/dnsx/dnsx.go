package main

import (
	"github.com/projectdiscovery/dnsx/internal/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	runner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// nolint:errcheck
	runner.Run()
	runner.Close()
}
