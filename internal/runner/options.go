package runner

import (
	"errors"
	"flag"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goconfig"
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
	Trace             bool
	TraceMaxRecursion int
	WildcardThreshold int
	WildcardDomain    string
	ShowStatistics    bool
	rcodes            map[int]struct{}
	RCode             string
	hasRCodes         bool
	Resume            bool
	ResumeFile        string
	resumeCfg         *ResumeCfg
	FlushInterval     int
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.Resolvers, "r", "", "List of resolvers (file or comma separated)")
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
	flag.BoolVar(&options.ShowStatistics, "stats", false, "Display stats of the running scan")
	flag.BoolVar(&options.Trace, "trace", false, "Perform dns trace")
	flag.IntVar(&options.TraceMaxRecursion, "trace-max-recursion", math.MaxInt16, "Max recursion for dns trace")
	flag.StringVar(&options.RCode, "rcode", "", "Response codes (eg. -rcode 0,1,2 or -rcode noerror,nxdomain)")
	flag.BoolVar(&options.Resume, "resume", false, "Enable stop/resume support")
	flag.StringVar(&options.ResumeFile, "resume-file", "resume.cfg", "Resume file name")
	flag.IntVar(&options.FlushInterval, "flush-interval", 10, "Flush interval of output file")

	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureRcodes()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	if options.Resume {
		err = options.configureResume()
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
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
	var resumeCfg ResumeCfg
	// attempt to load resume file - fail silently if it doesn't exist
	_ = goconfig.Load(&resumeCfg, options.ResumeFile)
	options.resumeCfg = &resumeCfg
	return nil
}
