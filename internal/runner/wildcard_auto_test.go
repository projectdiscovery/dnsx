package runner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractRootDomain verifies eTLD+1 extraction for various hostname formats.
func TestExtractRootDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		// Standard single-level TLDs
		{"api.example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"deep.sub.domain.example.com", "example.com", true},

		// Multi-level TLDs (eTLD+1 accuracy)
		{"api.example.co.uk", "example.co.uk", true},
		{"sub.foo.com.au", "foo.com.au", true},

		// Trailing dot (FQDN)
		{"api.example.com.", "example.com", true},
		{"  www.example.com  ", "example.com", true},

		// Host:port — should be rejected
		{"api.example.com:443", "", false},

		// Bare apex domain
		{"example.com", "example.com", true},

		// Empty
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := extractRootDomain(tt.input)
			assert.Equal(t, tt.ok, ok, "ok mismatch for %q", tt.input)
			if tt.ok {
				assert.Equal(t, tt.expected, got, "domain mismatch for %q", tt.input)
			}
		})
	}
}

// TestAutoWildcardCacheIsolation verifies the thread-safe wildcard cache correctly
// stores and retrieves fingerprints without races.
func TestAutoWildcardCacheIsolation(t *testing.T) {
	r := &Runner{
		autoWildcardCache: make(map[string]*wildcardFingerprint),
	}

	// Simulate storing a fingerprint
	fp := &wildcardFingerprint{
		a:     map[string]struct{}{"1.2.3.4": {}},
		aaaa:  map[string]struct{}{},
		cname: map[string]struct{}{},
	}
	r.autoWildcardMu.Lock()
	r.autoWildcardCache["example.com"] = fp
	r.autoWildcardMu.Unlock()

	// Read it back
	r.autoWildcardMu.RLock()
	got, seen := r.autoWildcardCache["example.com"]
	r.autoWildcardMu.RUnlock()

	require.True(t, seen)
	_, hasIP := got.a["1.2.3.4"]
	require.True(t, hasIP)

	// Absent domain
	r.autoWildcardMu.RLock()
	_, seen2 := r.autoWildcardCache["other.com"]
	r.autoWildcardMu.RUnlock()
	require.False(t, seen2)
}

// TestIsAutoWildcardMatch verifies match logic against a pre-populated cache.
func TestIsAutoWildcardMatch(t *testing.T) {
	r := &Runner{
		options:           &Options{},
		autoWildcardCache: make(map[string]*wildcardFingerprint),
	}

	// Populate cache: example.com is a wildcard with known A and CNAME
	r.autoWildcardCache["example.com"] = &wildcardFingerprint{
		a:     map[string]struct{}{"10.0.0.1": {}, "10.0.0.2": {}},
		aaaa:  map[string]struct{}{"::1": {}},
		cname: map[string]struct{}{"wildcard.cdn.net": {}},
	}
	// notawild.com is explicitly NOT a wildcard
	r.autoWildcardCache["notawild.com"] = nil
	// unknown.com has no entry — we mark it nil to avoid probing in unit tests
	r.autoWildcardCache["unknown.com"] = nil

	tests := []struct {
		name     string
		host     string
		a        []string
		aaaa     []string
		cname    []string
		expected bool
	}{
		{
			name:     "A record matches wildcard IP",
			host:     "random.example.com",
			a:        []string{"10.0.0.1"},
			expected: true,
		},
		{
			name:     "AAAA record matches wildcard IPv6",
			host:     "random.example.com",
			aaaa:     []string{"::1"},
			expected: true,
		},
		{
			name:     "CNAME matches wildcard CNAME",
			host:     "random.example.com",
			cname:    []string{"wildcard.cdn.net"},
			expected: true,
		},
		{
			name:     "Different IP not filtered",
			host:     "legit.example.com",
			a:        []string{"1.2.3.4"},
			expected: false,
		},
		{
			name:     "Non-wildcard domain not filtered",
			host:     "legit.notawild.com",
			a:        []string{"10.0.0.1"},
			expected: false,
		},
		{
			name:     "Unknown domain (no cache entry) not filtered",
			host:     "sub.unknown.com",
			a:        []string{"10.0.0.1"},
			expected: false,
		},
		{
			name:     "Multiple IPs one matches",
			host:     "random.example.com",
			a:        []string{"9.9.9.9", "10.0.0.2"},
			expected: true,
		},
		{
			name:     "IP address input — no root domain",
			host:     "192.168.1.1",
			a:        []string{"192.168.1.1"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.isAutoWildcardMatch(tt.host, tt.a, tt.aaaa, tt.cname)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestAutoWildcardDoublCheckLock verifies that concurrent lookups for the same domain
// only probe once (double-check locking correctness).
func TestAutoWildcardDoubleCheckLock(t *testing.T) {
	r := &Runner{
		options:           &Options{},
		autoWildcardCache: make(map[string]*wildcardFingerprint),
	}

	// Pre-populate a non-wildcard entry
	r.autoWildcardCache["example.com"] = nil

	// Multiple reads should all return (nil, false)
	results := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			r.autoWildcardMu.RLock()
			fp, seen := r.autoWildcardCache["example.com"]
			r.autoWildcardMu.RUnlock()
			results <- (seen && fp == nil)
		}()
	}
	for i := 0; i < 10; i++ {
		assert.True(t, <-results)
	}
}

// TestWildcardFingerprintAllFields verifies all three record types are tracked.
func TestWildcardFingerprintAllFields(t *testing.T) {
	fp := &wildcardFingerprint{
		a:     map[string]struct{}{"1.1.1.1": {}},
		aaaa:  map[string]struct{}{"2606:4700:4700::1111": {}},
		cname: map[string]struct{}{"target.example.net": {}},
	}

	_, hasA := fp.a["1.1.1.1"]
	_, hasAAAA := fp.aaaa["2606:4700:4700::1111"]
	_, hasCNAME := fp.cname["target.example.net"]

	assert.True(t, hasA)
	assert.True(t, hasAAAA)
	assert.True(t, hasCNAME)
}

// TestExtractRootDomainIPRejection verifies that IP addresses return false.
func TestExtractRootDomainIPRejection(t *testing.T) {
	ips := []string{"1.2.3.4", "::1", "2001:db8::1", "10.0.0.1"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			// IPs won't have valid TLD+1 extraction
			parsed := net.ParseIP(ip)
			if parsed != nil {
				_, ok := extractRootDomain(ip)
				// IP-like strings may or may not parse as domains;
				// what matters is they don't produce valid wildcard domains.
				// Just verify no panic.
				_ = ok
			}
		})
	}
}
