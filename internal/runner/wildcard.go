package runner

import (
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/utils/dns/wildcard"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type wildcardLookupAdapter struct {
	client    *dnsx.DNSX
	limiter   *ratelimit.Limiter
	extractor func(*retryabledns.DNSData) []string
	onLookup  func()
}

func newWildcardResolvers(dnsxClient *dnsx.DNSX, limiter *ratelimit.Limiter, onLookup func()) (*wildcard.Resolver, *wildcard.Resolver, *wildcardLookupAdapter, *wildcardLookupAdapter, *sliceutil.SyncSlice[string], *mapsutil.SyncLockMap[string, struct{}], error) {
	domains := sliceutil.NewSyncSlice[string]()
	domainSet := mapsutil.NewSyncLockMap[string, struct{}]()

	aClient, err := newWildcardProbeClient(dnsxClient, dns.TypeA)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	aaaaClient, err := newWildcardProbeClient(dnsxClient, dns.TypeAAAA)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	aAdapter := &wildcardLookupAdapter{
		client:   aClient,
		limiter:  limiter,
		onLookup: onLookup,
		extractor: func(data *retryabledns.DNSData) []string {
			return data.A
		},
	}
	aaaaAdapter := &wildcardLookupAdapter{
		client:   aaaaClient,
		limiter:  limiter,
		onLookup: onLookup,
		extractor: func(data *retryabledns.DNSData) []string {
			return data.AAAA
		},
	}

	aResolver := wildcard.NewResolverWithDomains(domains, aAdapter.lookup)
	aaaaResolver := wildcard.NewResolverWithDomains(domains, aaaaAdapter.lookup)

	return aResolver, aaaaResolver, aAdapter, aaaaAdapter, domains, domainSet, nil
}

func newWildcardProbeClient(base *dnsx.DNSX, questionType uint16) (*dnsx.DNSX, error) {
	options := *base.Options
	options.QuestionTypes = []uint16{questionType}
	return dnsx.New(options)
}

func (a *wildcardLookupAdapter) lookup(host string) ([]string, error) {
	a.limiter.Take()
	if a.onLookup != nil {
		a.onLookup()
	}
	data, err := a.client.QueryOne(host)
	if err != nil {
		return nil, err
	}
	if data == nil || data.StatusCodeRaw != dns.RcodeSuccess {
		return nil, nil
	}
	return a.extractor(data), nil
}

func dnsDataAAnswers(data *retryabledns.DNSData) []string {
	if data == nil {
		return nil
	}
	return data.A
}

func dnsDataAAAAAnswers(data *retryabledns.DNSData) []string {
	if data == nil {
		return nil
	}
	return data.AAAA
}

func (r *Runner) ensureWildcardRoot(root string) {
	if root == "" {
		return
	}
	if _, ok := r.wildcardDomainSet.Get(root); ok {
		return
	}
	_ = r.wildcardDomainSet.Set(root, struct{}{})
	r.wildcardDomains.Append(root)
}

func (r *Runner) filterWildcardHosts() error {
	if r.options.WildcardDomain != "" {
		r.ensureWildcardRoot(r.options.WildcardDomain)
		return r.filterWildcardDomain()
	}
	return nil
}

func (r *Runner) filterWildcardDomain() error {
	gologger.Print().Msgf("Starting to filter wildcard subdomains\n")

	ipDomain := make(map[string]map[string]struct{})
	listIPs := []string{}

	r.hm.Scan(func(k, v []byte) error {
		var dnsdata retryabledns.DNSData
		if err := json.Unmarshal(v, &dnsdata); err != nil {
			return nil
		}

		for _, address := range dnsdata.A {
			if _, ok := ipDomain[address]; !ok {
				ipDomain[address] = make(map[string]struct{})
				listIPs = append(listIPs, address)
			}
			ipDomain[address][string(k)] = struct{}{}
		}

		return nil
	})

	jobs := make([]wildcardJob, 0)
	seen := make(map[string]struct{})
	for _, address := range listIPs {
		hosts := ipDomain[address]
		if len(hosts) < r.options.WildcardThreshold {
			continue
		}
		for host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			jobs = append(jobs, wildcardJob{host: host, root: r.options.WildcardDomain})
		}
	}

	r.startWildcardWorkers(len(jobs))
	for _, job := range jobs {
		r.wildcardworkerchan <- job
	}

	r.stopWildcardWorkers()

	r.startOutputWorker()
	seen = make(map[string]struct{})
	seenRemovedSubdomains := make(map[string]struct{})
	numRemovedSubdomains := 0
	for _, address := range listIPs {
		for host := range ipDomain[address] {
			if host == r.options.WildcardDomain || !r.wildcards.Has(host) {
				if _, ok := seen[host]; ok {
					continue
				}
				seen[host] = struct{}{}
				if err := r.lookupAndOutput(host); err != nil {
					return err
				}
				continue
			}
			if _, ok := seenRemovedSubdomains[host]; ok {
				continue
			}
			numRemovedSubdomains++
			seenRemovedSubdomains[host] = struct{}{}
		}
	}
	close(r.outputchan)
	r.wgoutputworker.Wait()

	gologger.Print().Msgf("%d wildcard subdomains removed\n", numRemovedSubdomains)
	return nil
}

func (r *Runner) startWildcardWorkers(numJobs int) {
	numThreads := r.options.Threads
	if numThreads > numJobs {
		numThreads = numJobs
	}
	for i := 0; i < numThreads; i++ {
		r.wgwildcardworker.Add(1)
		go r.wildcardWorker()
	}
}

func (r *Runner) stopWildcardWorkers() {
	close(r.wildcardworkerchan)
	r.wgwildcardworker.Wait()
	r.wildcardworkerchan = make(chan wildcardJob)
}

func (r *Runner) shouldAutoFilterHost(host string, dnsdata *retryabledns.DNSData) bool {
	root, ok := wildcard.RegistrableRoot(host)
	if !ok {
		return false
	}
	r.ensureWildcardRoot(root)

	aAnswers := dnsDataAAnswers(dnsdata)
	if len(aAnswers) == 0 {
		resolved, err := r.wildcardAAdapter.lookup(host)
		if err != nil {
			gologger.Debug().Msgf("failed wildcard A lookup for %s: %v\n", host, err)
		} else {
			aAnswers = resolved
		}
	}
	if len(aAnswers) > 0 {
		if matched, _ := r.wildcardAResolver.LookupHost(host, aAnswers); matched {
			return true
		}
	}

	aaaaAnswers := dnsDataAAAAAnswers(dnsdata)
	if len(aaaaAnswers) == 0 {
		resolved, err := r.wildcardAAAAAdapter.lookup(host)
		if err != nil {
			gologger.Debug().Msgf("failed wildcard AAAA lookup for %s: %v\n", host, err)
		} else {
			aaaaAnswers = resolved
		}
	}
	if len(aaaaAnswers) > 0 {
		if matched, _ := r.wildcardAAAAResolver.LookupHost(host, aaaaAnswers); matched {
			return true
		}
	}

	return false
}
