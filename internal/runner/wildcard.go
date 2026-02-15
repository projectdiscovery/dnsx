package runner

import (
	"strings"
	"sync"

	"github.com/rs/xid"
)

// IsWildcard checks if a host is wildcard
func (r *Runner) IsWildcard(host string) bool {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	subdomainPart := strings.TrimSuffix(host, "."+r.options.WildcardDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, r.options.WildcardDomain)

	if len(subdomainTokens) > 0 {
		for i := 1; i < len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + r.options.WildcardDomain
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

// isStrictWildcard checks if a domain is a wildcard root.
// Unlike IsWildcard (which compares IPs and requires -wd to specify the domain),
// this just checks if a random subdomain resolves at all — works for load-balanced wildcards.
func (r *Runner) isStrictWildcard(domain string) bool {
	randomHost := xid.New().String() + "." + domain
	resp, err := r.wildcardDnsx.QueryOne(randomHost)
	if err != nil || resp == nil {
		return false
	}
	return len(resp.A) > 0
}

// detectWildcardRoots finds all wildcard roots from a list of resolved hosts.
// Tests candidates top-down (shallowest first) so that finding *.example.com
// skips testing *.sub.example.com.
func (r *Runner) detectWildcardRoots(hosts []string) map[string]struct{} {
	allCandidates := make(map[string]struct{})
	for _, host := range hosts {
		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			continue
		}
		for i := 1; i < len(parts)-1; i++ {
			candidate := strings.Join(parts[i:], ".")
			allCandidates[candidate] = struct{}{}
		}
	}

	byDepth := make(map[int][]string)
	maxDepth := 0
	for candidate := range allCandidates {
		depth := strings.Count(candidate, ".") + 1
		byDepth[depth] = append(byDepth[depth], candidate)
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	roots := make(map[string]struct{})

	for depth := 2; depth <= maxDepth; depth++ {
		candidates := byDepth[depth]
		if len(candidates) == 0 {
			continue
		}

		var toTest []string
		for _, c := range candidates {
			if !isSubdomainOfWildcard(c, roots) {
				toTest = append(toTest, c)
			}
		}
		if len(toTest) == 0 {
			continue
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, r.options.Threads)
		var mu sync.Mutex
		for _, domain := range toTest {
			wg.Add(1)
			sem <- struct{}{}
			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()
				if r.isStrictWildcard(d) {
					mu.Lock()
					roots[d] = struct{}{}
					mu.Unlock()
				}
			}(domain)
		}
		wg.Wait()
	}

	return roots
}

func isSubdomainOfWildcard(host string, roots map[string]struct{}) bool {
	for root := range roots {
		if host != root && strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}
