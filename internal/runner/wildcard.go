package runner

import (
	"strings"

	"github.com/rs/xid"
)

// IsWildcard checks if a host is wildcard using the configured -wd/--wildcard-domain.
func (r *Runner) IsWildcard(host string) bool {
	return r.IsWildcardWithDomain(host, r.options.WildcardDomain)
}

// IsWildcardWithDomain checks if a host resolves to wildcard DNS answers for the given base domain.
func (r *Runner) IsWildcardWithDomain(host, wildcardDomain string) bool {
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

	// We use a rand prefix at the beginning like %rand%.domain.tld.
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

		for _, A := range listip {
			wildcards[A] = struct{}{}
		}
	}

	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true
		}
	}

	return false
}
