package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractRootDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple subdomain",
			input:    "foo.example.com",
			expected: "example.com",
		},
		{
			name:     "deep subdomain",
			input:    "a.b.c.example.com",
			expected: "example.com",
		},
		{
			name:     "root domain only",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "co.uk domain",
			input:    "sub.example.co.uk",
			expected: "example.co.uk",
		},
		{
			name:     "trailing dot",
			input:    "foo.example.com.",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRootDomain(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestAutoWildcardFilter_isAutoWildcard(t *testing.T) {
	awf := newAutoWildcardFilter()

	// Set up wildcard IPs for example.com
	awf.wildcardIPs["example.com"] = map[string]struct{}{
		"1.2.3.4": {},
		"5.6.7.8": {},
	}

	tests := []struct {
		name     string
		host     string
		aRecords []string
		expected bool
	}{
		{
			name:     "all records match wildcard",
			host:     "test.example.com",
			aRecords: []string{"1.2.3.4"},
			expected: true,
		},
		{
			name:     "multiple records all match wildcard",
			host:     "test.example.com",
			aRecords: []string{"1.2.3.4", "5.6.7.8"},
			expected: true,
		},
		{
			name:     "some records do not match wildcard",
			host:     "test.example.com",
			aRecords: []string{"1.2.3.4", "9.9.9.9"},
			expected: false,
		},
		{
			name:     "no records match wildcard",
			host:     "test.example.com",
			aRecords: []string{"9.9.9.9"},
			expected: false,
		},
		{
			name:     "empty A records",
			host:     "test.example.com",
			aRecords: []string{},
			expected: false,
		},
		{
			name:     "nil A records",
			host:     "test.example.com",
			aRecords: nil,
			expected: false,
		},
		{
			name:     "domain without wildcard",
			host:     "test.other.com",
			aRecords: []string{"1.2.3.4"},
			expected: false,
		},
		{
			name:     "deep subdomain matches wildcard",
			host:     "a.b.c.example.com",
			aRecords: []string{"1.2.3.4"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := awf.isAutoWildcard(tt.host, tt.aRecords)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestNewAutoWildcardFilter(t *testing.T) {
	awf := newAutoWildcardFilter()
	require.NotNil(t, awf)
	require.NotNil(t, awf.wildcardIPs)
	require.Empty(t, awf.wildcardIPs)
}
