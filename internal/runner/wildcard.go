package runner

import (
	"net"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// numWildcardProbes is the number of random subdomain probes per domain.
// Using 3 probes significantly reduces false negatives caused by intermittent DNS.
const numWildcardProbes = 3

// IsWildcard checks if a host is a wildcard for the given root domain.
// It is used by the existing -wd (wildcard-domain) post-processing flow.
func (r *Runner) IsWildcard(host, wildcardDomain string) bool {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	subdomainPart := strings.TrimSuffix(host, "."+wildcardDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, wildcardDomain)

	if len(subdomainTokens) > 0 {
		for i := 1; i < len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + wildcardDomain
			hosts = append(hosts, newhost)
		}
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		r.wildcardscachemutex.Lock()
		listip, ok := r.wildcardscache[h]
		r.wildcardscachemutex.Unlock()
		if !ok {
			in, err := r.dnsx.QueryOne(xid.New().String() + "." + h)
			if err != nil || in == nil {
				continue
			}
			listip = in.A
			r.wildcardscachemutex.Lock()
			r.wildcardscache[h] = in.A
			r.wildcardscachemutex.Unlock()
		}

		// Get all the records and add them to the wildcard map
		for _, A := range listip {
			if _, ok := wildcards[A]; !ok {
				wildcards[A] = struct{}{}
			}
		}
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true
		}
	}

	return false
}

// extractRootDomain extracts the eTLD+1 (registered domain) from a hostname.
// Uses publicsuffix-go for accurate multi-level TLD handling (e.g. co.uk, com.au).
// Falls back to simple last-two-labels heuristic if parsing fails.
// Returns ("", false) for IP addresses, host:port, or unparseable inputs.
func extractRootDomain(host string) (string, bool) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", false
	}
	// Reject host:port style inputs
	if idx := strings.LastIndex(host, ":"); idx > strings.LastIndex(host, ".") {
		return "", false
	}
	// Reject raw IP addresses (IPv4 and IPv6)
	if net.ParseIP(host) != nil {
		return "", false
	}

	dom, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil && dom != "" {
		return dom, true
	}

	// Fallback: use last two labels
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", false
	}
	return strings.Join(parts[len(parts)-2:], "."), true
}

// wildcardFingerprint holds the unique A, AAAA, and CNAME values observed
// when probing a wildcard domain with random subdomains.
type wildcardFingerprint struct {
	a     map[string]struct{}
	aaaa  map[string]struct{}
	cname map[string]struct{}
}

// probeWildcardDomain performs numWildcardProbes random subdomain lookups for `domain`
// and returns a wildcardFingerprint if any probe resolves (indicating wildcard DNS).
// Returns nil if the domain does not have wildcard DNS.
// Uses both A and CNAME queries to detect all wildcard flavours.
func (r *Runner) probeWildcardDomain(domain string) *wildcardFingerprint {
	fp := &wildcardFingerprint{
		a:     make(map[string]struct{}),
		aaaa:  make(map[string]struct{}),
		cname: make(map[string]struct{}),
	}

	anyResolved := false
	for i := 0; i < numWildcardProbes; i++ {
		randHost := xid.New().String() + "." + domain

		// A/AAAA probe (QueryOne uses the first configured question type — TypeA by default)
		if inA, err := r.dnsx.QueryOne(randHost); err == nil && inA != nil {
			for _, ip := range inA.A {
				fp.a[ip] = struct{}{}
			}
			for _, ip := range inA.AAAA {
				fp.aaaa[ip] = struct{}{}
			}
			for _, cn := range inA.CNAME {
				fp.cname[cn] = struct{}{}
			}
			if len(inA.A) > 0 || len(inA.AAAA) > 0 || len(inA.CNAME) > 0 {
				anyResolved = true
			}
		}

		// Explicit CNAME probe to catch pure-CNAME wildcards (e.g. *.example.com → alias.cdn.net)
		if inC, err := r.dnsx.QueryType(randHost, miekgdns.TypeCNAME); err == nil && inC != nil {
			for _, cn := range inC.CNAME {
				fp.cname[cn] = struct{}{}
			}
			if len(inC.CNAME) > 0 {
				anyResolved = true
			}
		}
	}

	if !anyResolved {
		return nil
	}
	return fp
}

// getAutoWildcardFingerprint returns the cached wildcard fingerprint for a root domain,
// probing lazily if not yet seen. Thread-safe via RWMutex.
// Returns (nil, false) when the domain is not a wildcard.
func (r *Runner) getAutoWildcardFingerprint(rootDomain string) (*wildcardFingerprint, bool) {
	r.autoWildcardMu.RLock()
	fp, seen := r.autoWildcardCache[rootDomain]
	r.autoWildcardMu.RUnlock()
	if seen {
		return fp, fp != nil
	}

	// Not yet probed — acquire write lock and probe (double-check idiom)
	r.autoWildcardMu.Lock()
	if fp, seen = r.autoWildcardCache[rootDomain]; seen {
		r.autoWildcardMu.Unlock()
		return fp, fp != nil
	}
	fp = r.probeWildcardDomain(rootDomain)
	r.autoWildcardCache[rootDomain] = fp
	r.autoWildcardMu.Unlock()

	if fp != nil {
		gologger.Info().Msgf("[auto-wildcard] Detected wildcard domain: *.%s\n", rootDomain)
	}

	return fp, fp != nil
}

// isAutoWildcardMatch returns true if the resolved hostname's DNS records (A, AAAA, CNAME)
// match the wildcard fingerprint for its eTLD+1 root domain.
// When true, the record should be filtered from output.
func (r *Runner) isAutoWildcardMatch(host string, a, aaaa, cname []string) bool {
	rootDomain, ok := extractRootDomain(host)
	if !ok {
		return false
	}

	fp, isWildcard := r.getAutoWildcardFingerprint(rootDomain)
	if !isWildcard {
		return false
	}

	for _, ip := range a {
		if _, ok := fp.a[ip]; ok {
			return true
		}
	}
	for _, ip := range aaaa {
		if _, ok := fp.aaaa[ip]; ok {
			return true
		}
	}
	for _, cn := range cname {
		if _, ok := fp.cname[cn]; ok {
			return true
		}
	}

	return false
}
