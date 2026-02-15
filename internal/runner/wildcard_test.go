package runner

import (
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/stretchr/testify/require"
)

// newTestRunner creates a minimal Runner with a real DNS client for wildcard testing.
func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	options := dnsx.DefaultOptions
	options.QuestionTypes = []uint16{1} // TypeA
	options.MaxRetries = 3
	dnsX, err := dnsx.New(options)
	require.NoError(t, err)
	return &Runner{
		dnsx:         dnsX,
		wildcardDnsx: dnsX,
		options: &Options{
			Threads: 100,
		},
	}
}

func TestIsSubdomainOfWildcard(t *testing.T) {
	roots := map[string]struct{}{
		"dev.projectdiscovery.io": {},
	}

	tests := []struct {
		host     string
		expected bool
	}{
		{"bob.dev.projectdiscovery.io", true},
		{"a.b.dev.projectdiscovery.io", true},
		{"dev.projectdiscovery.io", false},          // root itself is not filtered
		{"projectdiscovery.io", false},              // parent domain
		{"notprojectdiscovery.io", false},           // different domain
		{"dev.projectdiscovery.io.evil.com", false}, // suffix trick
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isSubdomainOfWildcard(tt.host, roots)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestIsStrictWildcard(t *testing.T) {
	r := newTestRunner(t)

	tests := []struct {
		domain   string
		expected bool
	}{
		{"dev.projectdiscovery.io", true}, // wildcard
		{"projectdiscovery.io", false},    // not wildcard
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := r.isStrictWildcard(tt.domain)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestDetectWildcardRoots(t *testing.T) {
	r := newTestRunner(t)

	hosts := []string{
		"bob.dev.projectdiscovery.io",
		"alice.dev.projectdiscovery.io",
		"blog.projectdiscovery.io",
	}

	roots := r.detectWildcardRoots(hosts)

	_, hasDev := roots["dev.projectdiscovery.io"]
	require.True(t, hasDev, "dev.projectdiscovery.io should be detected as wildcard root")

	_, hasPD := roots["projectdiscovery.io"]
	require.False(t, hasPD, "projectdiscovery.io should not be detected as wildcard root")

	// subdomains should be filtered, non-wildcard siblings should not
	require.True(t, isSubdomainOfWildcard("bob.dev.projectdiscovery.io", roots))
	require.False(t, isSubdomainOfWildcard("blog.projectdiscovery.io", roots))
}
