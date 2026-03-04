package runner

import (
	"sort"
	"sync"

	"golang.org/x/net/publicsuffix"
	"github.com/rs/xid"
	"golang.org/x/sync/singleflight"
)

// AutoWildcardDetector handles automatic wildcard DNS detection per root domain.
type AutoWildcardDetector struct {
	runner *Runner
	cache  map[string]map[string]struct{}
	mu     sync.Mutex
	group  singleflight.Group
}

// NewAutoWildcardDetector initializes a detector.
func NewAutoWildcardDetector(r *Runner) *AutoWildcardDetector {
	return &AutoWildcardDetector{
		runner: r,
		cache:  make(map[string]map[string]struct{}),
	}
}

// WildcardIPsForDomain returns the set of wildcard IPs for a given root domain, detecting and caching as needed.
func (d *AutoWildcardDetector) WildcardIPsForDomain(root string) (map[string]struct{}, error) {
	// check cache
	d.mu.Lock()
	if ips, ok := d.cache[root]; ok {
		d.mu.Unlock()
		return ips, nil
	}
	d.mu.Unlock()

	// use singleflight to prevent duplicate probes
	v, _, _ := d.group.Do(root, func() (interface{}, error) {
		// perform multiple random probes
		var records [][]string
		for i := 0; i < 3; i++ {
			rand := xid.New().String()
			host := rand + "." + root
			resp, err := d.runner.dnsx.QueryOne(host)
			if err != nil || resp == nil || len(resp.A) == 0 {
				return nil, nil // no wildcard
			}
			// copy and sort
			a := append([]string{}, resp.A...)
			sort.Strings(a)
			records = append(records, a)
		}
		// check all runs match
		first := records[0]
		for _, rec := range records[1:] {
			if len(rec) != len(first) {
				return nil, nil
			}
			for i := range rec {
				if rec[i] != first[i] {
					return nil, nil
				}
			}
		}
		// build set
		set := make(map[string]struct{})
		for _, ip := range first {
			set[ip] = struct{}{}
		}
		// cache
		d.mu.Lock()
		d.cache[root] = set
		d.mu.Unlock()
		return set, nil
	})
	if v == nil {
		return nil, nil
	}
	ips := v.(map[string]struct{})
	return ips, nil
}
