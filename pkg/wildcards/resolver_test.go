package wildcards

import (
	"fmt"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func Test_generateWildcardPermutations(t *testing.T) {
	var tests = []struct {
		subdomain string
		domain    string
		expected  []string
	}{
		{"test", "example.com", []string{"*.example.com"}},
		{"abc.test", "example.com", []string{"*.example.com", "*.test.example.com"}},
		{"xyz.abc.test", "example.com", []string{"*.example.com", "*.test.example.com", "*.abc.test.example.com"}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s.%s", test.subdomain, test.domain), func(t *testing.T) {
			result := generateWildcardPermutations(test.subdomain, test.domain)
			if len(result) != len(test.expected) {
				t.Fatalf("expected %d permutations, got %d", len(test.expected), len(result))
			}
			for i, r := range result {
				if r != test.expected[i] {
					t.Fatalf("expected %s, got %s", test.expected[i], r)
				}
			}
		})
	}
}

func Test_Resolver_LookupHost(t *testing.T) {
	resolver, err := NewResolver([]string{"google.com"}, 3, []string{
		"8.8.8.8",
	})
	require.NoError(t, err)

	lookupAndResolve := func(subdomain string, r *Resolver) (bool, map[string]struct{}) {
		ips, err := r.client.Lookup(subdomain)
		require.NoError(t, err)
		require.NotEmpty(t, ips)

		return resolver.LookupHost(subdomain, ips[0])
	}
	t.Run("normal", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve("www.google.com", resolver)
		require.False(t, isWildcard)
		require.Empty(t, wildcards)
	})

	t.Run("wildcard-root-domain", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve("campaigns.google.com", resolver)
		require.False(t, isWildcard)
		require.Empty(t, wildcards)
	})

	t.Run("wildcard", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve(xid.New().String()+".campaigns.google.com", resolver)
		require.True(t, isWildcard)
		require.NotEmpty(t, wildcards)
		fmt.Printf("wildcards: %v\n", wildcards)
	})
}
