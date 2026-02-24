package runner

import (
	"strings"

	"github.com/rs/xid"
)

// wildcardHosts returns the list of base domains at each subdomain level that
// should be probed with a random prefix to detect wildcard DNS.
// e.g. for host="deep.sub.example.com", baseDomain="example.com" it returns
// ["example.com", "sub.example.com"].
func wildcardHosts(host, baseDomain string) []string {
	var hosts []string
	hosts = append(hosts, baseDomain)

	subdomainPart := strings.TrimSuffix(host, "."+baseDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	if len(subdomainTokens) > 0 {
		for i := 1; i < len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + baseDomain
			hosts = append(hosts, newhost)
		}
	}
	return hosts
}

// IsWildcard checks if a host is a wildcard subdomain under baseDomain.
func (r *Runner) IsWildcard(host, baseDomain string) bool {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range wildcardHosts(host, baseDomain) {
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
