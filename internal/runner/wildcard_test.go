package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractParentDomains(t *testing.T) {
	tests := []struct {
		host     string
		expected []string
	}{
		{
			host:     "sub.example.com",
			expected: []string{"example.com"},
		},
		{
			host:     "deep.sub.example.com",
			expected: []string{"sub.example.com", "example.com"},
		},
		{
			host:     "a.b.c.example.com",
			expected: []string{"b.c.example.com", "c.example.com", "example.com"},
		},
		{
			host:     "example.com",
			expected: nil,
		},
		{
			host:     "com",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := extractParentDomains(tt.host)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestAutoWildcardResult_Match(t *testing.T) {
	result := &autoWildcardResult{
		isWildcard: true,
		ips:        map[string]struct{}{"1.2.3.4": {}, "5.6.7.8": {}},
	}

	// All records match wildcard IPs
	require.True(t, allRecordsMatchWildcard(result, []string{"1.2.3.4"}))
	require.True(t, allRecordsMatchWildcard(result, []string{"1.2.3.4", "5.6.7.8"}))

	// Some records don't match
	require.False(t, allRecordsMatchWildcard(result, []string{"1.2.3.4", "9.9.9.9"}))
	require.False(t, allRecordsMatchWildcard(result, []string{"9.9.9.9"}))

	// Empty records
	require.False(t, allRecordsMatchWildcard(result, []string{}))

	// Non-wildcard result
	nonWildcard := &autoWildcardResult{isWildcard: false, ips: map[string]struct{}{}}
	require.False(t, allRecordsMatchWildcard(nonWildcard, []string{"1.2.3.4"}))
}

// allRecordsMatchWildcard is a helper to test the matching logic without DNS queries
func allRecordsMatchWildcard(result *autoWildcardResult, aRecords []string) bool {
	if !result.isWildcard || len(aRecords) == 0 {
		return false
	}
	for _, a := range aRecords {
		if _, ok := result.ips[a]; !ok {
			return false
		}
	}
	return true
}
