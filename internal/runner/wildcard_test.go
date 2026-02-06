package runner

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParentDomains(t *testing.T) {
	tests := []struct {
		host     string
		expected []string
	}{
		{
			host:     "a.b.example.com",
			expected: []string{"b.example.com", "example.com"},
		},
		{
			host:     "sub.example.com",
			expected: []string{"example.com"},
		},
		{
			host:     "example.com",
			expected: nil,
		},
		{
			host:     "a.b.c.d.example.com",
			expected: []string{"b.c.d.example.com", "c.d.example.com", "d.example.com", "example.com"},
		},
		{
			host:     "com",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := parentDomains(tt.host)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestMapsToSlice(t *testing.T) {
	m := map[string]struct{}{
		"1.2.3.4": {},
		"5.6.7.8": {},
	}
	result := mapsToSlice(m)
	require.Len(t, result, 2)
	require.Contains(t, result, "1.2.3.4")
	require.Contains(t, result, "5.6.7.8")
}

func TestWildcardDetector_IsWildcardResponse_NoParent(t *testing.T) {
	// For a root domain (e.g., example.com), parentDomains returns nil,
	// so IsWildcardResponse should return false.
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}
	// no DNS client set — but since there's no parent domain to probe, it won't be called
	result := wd.IsWildcardResponse("example.com", []string{"1.2.3.4"})
	require.False(t, result, "root domain should not be detected as wildcard")
}

func TestWildcardDetector_CachedWildcard(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	// Pre-populate cache with a known wildcard entry
	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: true,
		ips:        map[string]struct{}{"1.2.3.4": {}, "5.6.7.8": {}},
	}

	// Should detect sub.example.com resolving to wildcard IPs
	result := wd.IsWildcardResponse("sub.example.com", []string{"1.2.3.4"})
	require.True(t, result, "should detect wildcard from cached entry")

	// Should NOT filter if IP is different from wildcard
	result = wd.IsWildcardResponse("sub.example.com", []string{"9.9.9.9"})
	require.False(t, result, "should not filter non-wildcard IP")

	// Should NOT filter if only some IPs match wildcard
	result = wd.IsWildcardResponse("sub.example.com", []string{"1.2.3.4", "9.9.9.9"})
	require.False(t, result, "should not filter partial wildcard match")

	// Should filter if all IPs match wildcard
	result = wd.IsWildcardResponse("sub.example.com", []string{"1.2.3.4", "5.6.7.8"})
	require.True(t, result, "should filter when all IPs match wildcard")
}

func TestWildcardDetector_CachedNonWildcard(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	// Pre-populate cache with a non-wildcard entry
	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: false,
		ips:        map[string]struct{}{},
	}

	result := wd.IsWildcardResponse("sub.example.com", []string{"1.2.3.4"})
	require.False(t, result, "non-wildcard domain should not be filtered")
}

func TestWildcardDetector_FilteredCount(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: true,
		ips:        map[string]struct{}{"1.2.3.4": {}},
	}

	require.Equal(t, int64(0), wd.FilteredCount())

	wd.IsWildcardResponse("a.example.com", []string{"1.2.3.4"})
	require.Equal(t, int64(1), wd.FilteredCount())

	wd.IsWildcardResponse("b.example.com", []string{"1.2.3.4"})
	require.Equal(t, int64(2), wd.FilteredCount())

	// Non-matching should not increment
	wd.IsWildcardResponse("c.example.com", []string{"9.9.9.9"})
	require.Equal(t, int64(2), wd.FilteredCount())
}

func TestWildcardDetector_EmptyIPs(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: true,
		ips:        map[string]struct{}{"1.2.3.4": {}},
	}

	// Empty resolved IPs should return false
	result := wd.IsWildcardResponse("sub.example.com", []string{})
	require.False(t, result, "empty IPs should not be considered wildcard")

	result = wd.IsWildcardResponse("sub.example.com", nil)
	require.False(t, result, "nil IPs should not be considered wildcard")
}

func TestWildcardDetector_NestedSubdomain(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	// Wildcard only on deeper subdomain level
	wd.cache["sub.example.com"] = &wildcardCacheEntry{
		isWildcard: true,
		ips:        map[string]struct{}{"10.0.0.1": {}},
	}
	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: false,
		ips:        map[string]struct{}{},
	}

	// a.sub.example.com should be filtered (parent sub.example.com is wildcard)
	result := wd.IsWildcardResponse("a.sub.example.com", []string{"10.0.0.1"})
	require.True(t, result, "nested wildcard should be detected")

	// a.example.com should NOT be filtered (parent example.com is not wildcard)
	result = wd.IsWildcardResponse("a.example.com", []string{"10.0.0.1"})
	require.False(t, result, "non-wildcard parent should not filter")
}

func TestWildcardDetector_ConcurrentAccess(t *testing.T) {
	wd := &WildcardDetector{
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: 2,
		numProbes: 3,
	}

	wd.cache["example.com"] = &wildcardCacheEntry{
		isWildcard: true,
		ips:        map[string]struct{}{"1.2.3.4": {}},
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			host := fmt.Sprintf("sub%d.example.com", n)
			wd.IsWildcardResponse(host, []string{"1.2.3.4"})
		}(i)
	}
	wg.Wait()

	require.Equal(t, int64(100), wd.FilteredCount(), "all concurrent accesses should be filtered")
}

func TestNewWildcardDetector_ThresholdClamping(t *testing.T) {
	// Threshold below 2 should be clamped to 2
	wd := NewWildcardDetector(nil, 0)
	require.Equal(t, 2, wd.threshold)

	wd = NewWildcardDetector(nil, 1)
	require.Equal(t, 2, wd.threshold)

	wd = NewWildcardDetector(nil, 5)
	require.Equal(t, 5, wd.threshold)
}
