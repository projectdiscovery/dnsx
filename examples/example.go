package main

import (
	"github.com/projectdiscovery/dnsx/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {

	options := &runner.Options{
		Domains:  "hackerone.com",
		WordList: "api,docs",
		RCode:    "",
		Threads:  2,
		Retries:  1,
		JSON:     true,
		Verbose:  true,
	}

	options.ValidateOptions()

	dnsxRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// nolint:errcheck
	dnsxRunner.Run()
	dnsxRunner.Close()

}
