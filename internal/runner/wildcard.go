package runner

import (
	"strings"

	iputil "github.com/projectdiscovery/utils/ip"
	"github.com/rs/xid"
)

var commonSecondLevelDomains = map[string]struct{}{
	"ac":  {},
	"co":  {},
	"com": {},
	"edu": {},
	"gov": {},
	"mil": {},
	"net": {},
	"org": {},
}

func wildcardBaseDomain(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if iputil.IsIP(host) {
		return ""
	}

	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) < 2 {
		return ""
	}

	last := labels[len(labels)-1]
	second := labels[len(labels)-2]
	if len(labels) >= 3 && len(last) == 2 {
		if _, ok := commonSecondLevelDomains[second]; ok {
			return strings.Join(labels[len(labels)-3:], ".")
		}
	}

	return strings.Join(labels[len(labels)-2:], ".")
}

// IsWildcard checks if a host is wildcard
func (r *Runner) IsWildcard(host, wildcardDomain string) bool {
	if wildcardDomain == "" {
		return false
	}
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
