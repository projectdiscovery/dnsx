package main

import (
	"os"
	"os/signal"

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

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Fatal().Msgf("CTRL+C pressed: Exiting\n")
			runner.Close()
			os.Exit(1)
		}
	}()

	// nolint:errcheck
	runner.Run()
	runner.Close()
}
