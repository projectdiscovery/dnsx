package runner

import (
	"errors"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const (
	DefaultResumeFile = "resume.cfg"
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
	Trace             bool
	TraceMaxRecursion int
	WildcardThreshold int
	WildcardDomain    string
	ShowStatistics    bool
	rcodes            map[int]struct{}
	RCode             string
	hasRCodes         bool
	Resume            bool
	resumeCfg         *ResumeCfg
	FlushInterval     int
	HostsFile         bool
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using [retryabledns](https://github.com/projectdiscovery/retryabledns) library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers, additionally supports DNS wildcard filtering like [shuffledns](https://github.com/projectdiscovery/shuffledns).`)

	createGroup(flagSet, "rate-limit", "Rate-limit",
	flagSet.IntVar(&options.Threads, "t", 100, "Number of concurrent threads to make"),
	flagSet.IntVar(&options.RateLimit, "rl", -1, "Number of DNS request/second"),
	)

	createGroup(flagSet, "output", "Output",
	flagSet.StringVar(&options.OutputFile, "o", "", "File to write output to (optional)"),
	flagSet.BoolVar(&options.JSON, "json", false, "JSON output"),
	)

	createGroup(flagSet, "debug", "Debug",
	flagSet.BoolVar(&options.Silent, "silent", false, "Show only results in the output"),
	flagSet.BoolVar(&options.Verbose, "verbose", false, "Verbose output"),
	flagSet.BoolVar(&options.Version, "version", false, "Show version of dnsx"),
	flagSet.BoolVar(&options.ShowStatistics, "stats", false, "Display stats of the running scan"),
	flagSet.BoolVar(&options.Response, "resp", false, "Display response data"),
	)

	createGroup(flagSet, "input", "Input",
	flagSet.StringVar(&options.Resolvers, "r", "", "List of resolvers (file or comma separated)"),
	flagSet.StringVar(&options.Hosts, "l", "", "File input with list of subdomains"),
	)

	createGroup(flagSet, "optimization", "Optimization",
	flagSet.IntVar(&options.Retries, "retry", 1, "Number of DNS retries"),
	flagSet.IntVar(&options.FlushInterval, "flush-interval", 10, "Flush interval of output file"),
	)

	createGroup(flagSet, "record-type", "Record-Type",
	flagSet.BoolVar(&options.A, "a", false, "Query A record"),
	flagSet.BoolVar(&options.AAAA, "aaaa", false, "Query AAAA record"),
	flagSet.BoolVar(&options.NS, "ns", false, "Query NS record"),
	flagSet.BoolVar(&options.CNAME, "cname", false, "Query CNAME record"),
	flagSet.BoolVar(&options.PTR, "ptr", false, "Query PTR record"),
	flagSet.BoolVar(&options.MX, "mx", false, "Query MX record"),
	flagSet.BoolVar(&options.SOA, "soa", false, "Query SOA record"),
	flagSet.BoolVar(&options.TXT, "txt", false, "Query TXT record"),
    )

	createGroup(flagSet, "filters", "Filtering",
	flagSet.IntVar(&options.WildcardThreshold, "wt", 5, "Wildcard Filter Threshold"),
	flagSet.StringVar(&options.WildcardDomain, "wd", "", "Wildcard Top level domain for wildcard filtering (other flags will be ignored)"),
	flagSet.BoolVar(&options.ResponseOnly, "resp-only", false, "Display response data only"),
	)

	createGroup(flagSet, "configs", "Configurations",
	flagSet.BoolVar(&options.Raw, "raw", false, "Operates like dig"),
	flagSet.BoolVar(&options.Trace, "trace", false, "Perform dns trace"),
	flagSet.IntVar(&options.TraceMaxRecursion, "trace-max-recursion", math.MaxInt16, "Max recursion for dns trace"),
	flagSet.StringVar(&options.RCode, "rcode", "", "Response codes (eg. -rcode 0,1,2 or -rcode noerror,nxdomain)"),
	flagSet.BoolVar(&options.Resume, "resume", false, "Resume"),
	flagSet.BoolVar(&options.HostsFile, "hostsfile", false, "Parse host file"),
	)

	_ = flagSet.Parse()
	

	
	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureRcodes()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	err = options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

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

func (options *Options) configureRcodes() error {
	options.rcodes = make(map[int]struct{})
	rcodes := strings.Split(options.RCode, ",")
	for _, rcode := range rcodes {
		var rc int
		switch strings.ToLower(rcode) {
		case "":
			continue
		case "noerror":
			rc = 0
		case "formerr":
			rc = 1
		case "servfail":
			rc = 2
		case "nxdomain":
			rc = 3
		case "notimp":
			rc = 4
		case "refused":
			rc = 5
		case "yxdomain":
			rc = 6
		case "yxrrset":
			rc = 7
		case "nxrrset":
			rc = 8
		case "notauth":
			rc = 9
		case "notzone":
			rc = 10
		case "badsig", "badvers":
			rc = 16
		case "badkey":
			rc = 17
		case "badtime":
			rc = 18
		case "badmode":
			rc = 19
		case "badname":
			rc = 20
		case "badalg":
			rc = 21
		case "badtrunc":
			rc = 22
		case "badcookie":
			rc = 23
		default:
			var err error
			rc, err = strconv.Atoi(rcode)
			if err != nil {
				return errors.New("invalid rcode value")
			}
		}

		options.rcodes[rc] = struct{}{}
	}

	options.hasRCodes = options.RCode != ""

	// Set rcode to 0 if none was specified
	if len(options.rcodes) == 0 {
		options.rcodes[0] = struct{}{}
	}

	return nil
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}	
