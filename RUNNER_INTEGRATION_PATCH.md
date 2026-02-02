# Runner.go Integration Patch for Auto-Wildcard Detection

This document describes the changes needed in `internal/runner/runner.go` to integrate auto-wildcard detection.

## Changes to Runner Struct

```go
// Runner is a client for running the enumeration process.
type Runner struct {
	options              *Options
	dnsx                 *dnsx.DNSX
	wgoutputworker       *sync.WaitGroup
	wgresolveworkers     *sync.WaitGroup
	wgwildcardworker     *sync.WaitGroup
	workerchan           chan string
	outputchan           chan string
	wildcardworkerchan   chan string
	wildcards            *mapsutil.SyncLockMap[string, struct{}]
	wildcardscache       map[string][]string
	wildcardscachemutex  sync.Mutex
	autoWildcardDetector *AutoWildcardDetector  // ADD THIS LINE
	limiter              *ratelimit.Limiter
	hm                   *hybrid.HybridMap
	stats                clistats.StatisticsClient
	tmpStdinFile         string
	aurora               aurora.Aurora
}
```

## Changes to New() Function

Add initialization of auto-wildcard detector after creating the Runner:

```go
func New(options *Options) (*Runner, error) {
	// ... existing code ...

	r := Runner{
		options:            options,
		dnsx:               dnsX,
		wgoutputworker:     &sync.WaitGroup{},
		wgresolveworkers:   &sync.WaitGroup{},
		wgwildcardworker:   &sync.WaitGroup{},
		workerchan:         make(chan string),
		wildcardworkerchan: make(chan string),
		wildcards:          mapsutil.NewSyncLockMap[string, struct{}](),
		wildcardscache:     make(map[string][]string),
		limiter:            limiter,
		hm:                 hm,
		stats:              stats,
		aurora:             aurora.NewAurora(!options.NoColor),
	}

	// ADD THIS BLOCK
	if options.AutoWildcard {
		r.autoWildcardDetector = NewAutoWildcardDetector(&r)
		gologger.Info().Msgf("Auto-wildcard detection enabled\n")
	}

	return &r, nil
}
```

## Changes to worker() Function

Add wildcard filtering logic after DNS query, around line 650-700:

```go
func (r *Runner) worker() {
	defer r.wgresolveworkers.Done()
	for domain := range r.workerchan {
		if isURL(domain) {
			domain = extractDomain(domain)
		}
		r.limiter.Take()
		dnsData := dnsx.ResponseData{}
		// Ignoring errors as partial results are still good
		dnsData.DNSData, _ = r.dnsx.QueryMultiple(domain)
		// Just skipping nil responses (in case of critical errors)
		if dnsData.DNSData == nil {
			continue
		}

		if dnsData.Host == "" || dnsData.Timestamp.IsZero() {
			continue
		}

		// ADD THIS BLOCK - Auto-wildcard filtering
		if r.options.AutoWildcard && r.autoWildcardDetector != nil {
			if r.autoWildcardDetector.IsWildcardSubdomain(domain) {
				if r.options.Verbose {
					gologger.Verbose().Msgf("Filtered wildcard subdomain: %s\n", domain)
				}
				continue
			}
		}

		// results from hosts file are always returned
		if !dnsData.HostsFile {
			// skip responses not having the expected response code
			if len(r.options.rcodes) > 0 {
				if _, ok := r.options.rcodes[dnsData.StatusCodeRaw]; !ok {
					continue
				}
			}
		}

		// ... rest of the function continues ...
	}
}
```

## Summary Statistics (Optional Enhancement)

Add to the end of `run()` function to show wildcard detection stats:

```go
func (r *Runner) run() error {
	// ... existing code ...

	close(r.outputchan)
	r.wgoutputworker.Wait()

	// ADD THIS BLOCK - Show auto-wildcard stats
	if r.options.AutoWildcard && r.autoWildcardDetector != nil {
		domains := r.autoWildcardDetector.GetAllDomains()
		wildcardCount := 0
		for _, domain := range domains {
			info := r.autoWildcardDetector.GetDomainInfo(domain)
			if info != nil && info.IsWildcard {
				wildcardCount++
			}
		}
		gologger.Info().Msgf("Auto-wildcard detection: %d domains checked, %d wildcards detected\n", 
			len(domains), wildcardCount)
	}

	// ... existing wildcard filtering code for -wd flag ...

	return nil
}
```

## Complete Integration Steps

1. Add `autoWildcardDetector *AutoWildcardDetector` to Runner struct
2. Initialize detector in `New()` when `options.AutoWildcard` is true
3. Add filtering logic in `worker()` function after DNS query
4. (Optional) Add summary statistics at end of `run()`

## Testing the Integration

```bash
# Build the modified dnsx
go build ./cmd/dnsx

# Test with a known wildcard domain
echo "random123.example.com" | ./dnsx --auto-wildcard -v

# Test with multiple domains
cat << EOF | ./dnsx --auto-wildcard -json
api.example.com
test.example.com
admin.another.com
www.another.com
EOF
```

## Error Handling

The implementation includes:
- Nil checks for autoWildcardDetector
- Thread-safe operations with mutexes
- Graceful handling of DNS query failures
- Verbose logging for debugging

## Performance Impact

- **Minimal overhead**: Only 3 extra DNS queries per unique base domain
- **Caching**: Wildcard info cached after first detection
- **Concurrent-safe**: All operations protected by mutexes
- **No blocking**: Wildcard checks don't block main resolution flow
