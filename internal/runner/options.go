package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	Resolvers         string
	Hosts             string
	Threads           int
	RateLimit         int
	Retries           int
	OutputFormat      string
	OutputFile        string
	Raw               bool
	Silent            bool
	Verbose           bool
	Version           bool
	Response          bool
	ResponseOnly      bool
	A                 bool
	AAAA              bool
	NS                bool
	CNAME             bool
	PTR               bool
	MX                bool
	SOA               bool
	TXT               bool
	JSON              bool
	WildcardThreshold int
	WildcardDomain    string
	ShowStatistics    bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.Resolvers, "r", "", "List of resolvers (file or command separated)")
	flag.StringVar(&options.Hosts, "l", "", "File input with list of subdomains")
	flag.IntVar(&options.Threads, "t", 100, "Number of concurrent threads to make")
	flag.IntVar(&options.Retries, "retry", 1, "Number of DNS retries")
	flag.IntVar(&options.RateLimit, "rl", -1, "Number of DNS request/second")
	flag.StringVar(&options.OutputFile, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.Raw, "raw", false, "Operates like dig")
	flag.BoolVar(&options.Silent, "silent", false, "Show only results in the output")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&options.Version, "version", false, "Show version of dnsx")
	flag.BoolVar(&options.Response, "resp", false, "Display response data")
	flag.BoolVar(&options.ResponseOnly, "resp-only", false, "Display response data only")
	flag.BoolVar(&options.A, "a", false, "Query A record")
	flag.BoolVar(&options.AAAA, "aaaa", false, "Query AAAA record")
	flag.BoolVar(&options.NS, "ns", false, "Query NS record")
	flag.BoolVar(&options.CNAME, "cname", false, "Query CNAME record")
	flag.BoolVar(&options.PTR, "ptr", false, "Query PTR record")
	flag.BoolVar(&options.MX, "mx", false, "Query MX record")
	flag.BoolVar(&options.SOA, "soa", false, "Query SOA record")
	flag.BoolVar(&options.TXT, "txt", false, "Query TXT record")
	flag.BoolVar(&options.JSON, "json", false, "JSON output")
	flag.IntVar(&options.WildcardThreshold, "wt", 5, "Wildcard Filter Threshold")
	flag.StringVar(&options.WildcardDomain, "wd", "", "Wildcard Top level domain for wildcard filtering (other flags will be ignored)")
	flag.BoolVar(&options.ShowStatistics, "stats", false, "Enable statistic on keypress (terminal may become unresponsive till the end)")

	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.Response && options.ResponseOnly {
		gologger.Fatal().Msgf("resp and resp-only can't be used at the same time")
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
