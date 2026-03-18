package runner

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	"github.com/rs/xid"
)

const autoWildcardProbes = 3

// extractRootDomain extracts the root domain from a subdomain.
// For example, "www.sub.example.com" with known root "example.com" returns "example.com".
// Without a known root, it takes the last two labels.
func extractBaseDomain(host string) string {
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// AutoWildcardFilter automatically detects wildcard domains and filters results
func (r *Runner) AutoWildcardFilter() {
	// Collect all resolved hosts grouped by base domain
	baseDomainIPs := make(map[string]map[string]struct{}) // baseDomain -> ip -> set(hosts)
	baseDomainHosts := make(map[string][]string)           // baseDomain -> hosts

	// Collect all A records per host and group by base domain
	hostARecords := make(map[string][]string)
	r.hm.Scan(func(k, v []byte) error {
		var dnsdata retryabledns.DNSData
		if err := dnsdata.Unmarshal(v); err != nil {
			return nil
		}
		host := string(k)
		if len(dnsdata.A) > 0 {
			hostARecords[host] = dnsdata.A
			baseDomain := extractBaseDomain(host)
			if _, ok := baseDomainIPs[baseDomain]; !ok {
				baseDomainIPs[baseDomain] = make(map[string]struct{})
			}
			for _, a := range dnsdata.A {
				baseDomainIPs[baseDomain][a] = struct{}{}
			}
			baseDomainHosts[baseDomain] = append(baseDomainHosts[baseDomain], host)
		}
		return nil
	})

	if len(baseDomainHosts) == 0 {
		return
	}

	gologger.Print().Msgf("Starting auto-wildcard detection for %d domain(s)\n", len(baseDomainHosts))

	// For each base domain, probe random subdomains to detect wildcards
	wildcardIPs := make(map[string]map[string]struct{}) // baseDomain -> set of wildcard IPs

	for baseDomain := range baseDomainHosts {
		ips := r.probeBaseDomain(baseDomain)
		if len(ips) > 0 {
			wildcardIPs[baseDomain] = ips
			gologger.Verbose().Msgf("Auto-wildcard detected for %s\n", baseDomain)
		}
	}

	if len(wildcardIPs) == 0 {
		gologger.Print().Msgf("No wildcard domains detected\n")
		return
	}

	gologger.Print().Msgf("Detected %d wildcard domain(s), starting to filter\n", len(wildcardIPs))

	// Filter hosts: mark hosts whose IPs match wildcard IPs
	numRemoved := 0
	for baseDomain, wIPs := range wildcardIPs {
		hosts, ok := baseDomainHosts[baseDomain]
		if !ok {
			continue
		}
		for _, host := range hosts {
			aRecords := hostARecords[host]
			allWildcard := len(aRecords) > 0
			for _, ip := range aRecords {
				if _, ok := wIPs[ip]; !ok {
					allWildcard = false
					break
				}
			}
			if allWildcard {
				_ = r.wildcards.Set(host, struct{}{})
				numRemoved++
			}
		}
	}

	gologger.Print().Msgf("%d wildcard subdomains removed\n", numRemoved)
}

// probeBaseDomain probes a base domain with random subdomains to detect if it's a wildcard
func (r *Runner) probeBaseDomain(baseDomain string) map[string]struct{} {
	ipCount := make(map[string]int)

	for i := 0; i < autoWildcardProbes; i++ {
		probeHost := fmt.Sprintf("%s.%s", xid.New().String(), baseDomain)
		resp, err := r.dnsx.QueryOne(probeHost)
		if err != nil || resp == nil || len(resp.A) == 0 {
			// If any probe doesn't resolve, not a wildcard
			return nil
		}
		for _, a := range resp.A {
			ipCount[a]++
		}
	}

	// A domain is considered wildcard if all probes resolved to at least one common IP
	wildcardIPs := make(map[string]struct{})
	for ip, count := range ipCount {
		if count >= autoWildcardProbes {
			wildcardIPs[ip] = struct{}{}
		}
	}

	return wildcardIPs
}
