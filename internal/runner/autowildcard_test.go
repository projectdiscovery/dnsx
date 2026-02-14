package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractParentDomain(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "simple subdomain",
			host:     "sub.example.com",
			expected: "example.com",
		},
		{
			name:     "deep subdomain",
			host:     "a.b.c.example.com",
			expected: "b.c.example.com",
		},
		{
			name:     "bare domain returns empty",
			host:     "example.com",
			expected: "",
		},
		{
			name:     "single label returns empty",
			host:     "localhost",
			expected: "",
		},
		{
			name:     "trailing dot stripped",
			host:     "sub.example.com.",
			expected: "example.com",
		},
		{
			name:     "two-level tld subdomain",
			host:     "sub.example.co.uk",
			expected: "example.co.uk",
		},
		{
			name:     "empty string",
			host:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractParentDomain(tt.host)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestAutoWildcardDetector_IsWildcard_EmptyRecords(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs:        make(map[string]map[string]struct{}),
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          3,
	}
	// Empty A records should not be considered wildcard
	require.False(t, d.isWildcard("sub.example.com", nil))
	require.False(t, d.isWildcard("sub.example.com", []string{}))
}

func TestAutoWildcardDetector_IsWildcard_NoParent(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs:        make(map[string]map[string]struct{}),
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          3,
	}
	// Bare domain with no parent should not be considered wildcard
	require.False(t, d.isWildcard("example.com", []string{"1.2.3.4"}))
}

func TestAutoWildcardDetector_IsWildcard_KnownNonWildcard(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs:        make(map[string]map[string]struct{}),
		nonWildcardDomains: map[string]struct{}{"example.com": {}},
		numProbes:          3,
	}
	// Parent marked as non-wildcard should return false
	require.False(t, d.isWildcard("sub.example.com", []string{"1.2.3.4"}))
}

func TestAutoWildcardDetector_IsWildcard_KnownWildcard(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs: map[string]map[string]struct{}{
			"example.com": {"1.2.3.4": {}, "5.6.7.8": {}},
		},
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          3,
	}
	// A records that are a subset of wildcard IPs should be filtered
	require.True(t, d.isWildcard("sub.example.com", []string{"1.2.3.4"}))
	require.True(t, d.isWildcard("other.example.com", []string{"1.2.3.4", "5.6.7.8"}))

	// A records that include non-wildcard IPs should not be filtered
	require.False(t, d.isWildcard("legit.example.com", []string{"9.9.9.9"}))
	require.False(t, d.isWildcard("mixed.example.com", []string{"1.2.3.4", "9.9.9.9"}))
}

func TestAutoWildcardDetector_FilteredCount(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs: map[string]map[string]struct{}{
			"example.com": {"1.2.3.4": {}},
		},
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          3,
	}
	require.Equal(t, int64(0), d.filteredCount.Load())

	d.isWildcard("a.example.com", []string{"1.2.3.4"})
	require.Equal(t, int64(1), d.filteredCount.Load())

	d.isWildcard("b.example.com", []string{"1.2.3.4"})
	require.Equal(t, int64(2), d.filteredCount.Load())

	// Non-matching should not increment
	d.isWildcard("c.example.com", []string{"9.9.9.9"})
	require.Equal(t, int64(2), d.filteredCount.Load())
}

func TestAutoWildcardDetector_DeepSubdomain(t *testing.T) {
	d := &autoWildcardDetector{
		wildcardIPs: map[string]map[string]struct{}{
			"b.example.com": {"10.0.0.1": {}},
		},
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          3,
	}
	// "a.b.example.com" has parent "b.example.com" which is wildcard
	require.True(t, d.isWildcard("a.b.example.com", []string{"10.0.0.1"}))
	// "x.example.com" has parent "example.com" which is not in any list, so probing needed
	// Without a runner this would fail, but the parent "example.com" is not pre-populated so skip
}

func TestNewAutoWildcardDetector_MinProbes(t *testing.T) {
	// numProbes below 2 should be clamped to 2
	d := newAutoWildcardDetector(nil, 1)
	require.Equal(t, 2, d.numProbes)

	d = newAutoWildcardDetector(nil, 0)
	require.Equal(t, 2, d.numProbes)

	d = newAutoWildcardDetector(nil, 5)
	require.Equal(t, 5, d.numProbes)
}
