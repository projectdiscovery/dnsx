package runner

import (
	"testing"
)

func TestExtractRootDomain(t *testing.T) {
	awd := NewAutoWildcardDetector(nil)

	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"www.example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"test.github.io", "test.github.io"},
		{"sub.test.github.io", "test.github.io"},
	}

	for _, test := range tests {
		result := awd.extractRootDomain(test.input)
		if result != test.expected {
			t.Errorf("extractRootDomain(%s) = %s; expected %s", test.input, result, test.expected)
		}
	}
}

func TestGetParentDomains(t *testing.T) {
	awd := NewAutoWildcardDetector(nil)

	tests := []struct {
		input    string
		expected []string
	}{
		{
			"example.com",
			[]string{"example.com"},
		},
		{
			"www.example.com",
			[]string{"example.com", "www.example.com"},
		},
		{
			"a.b.c.example.com",
			[]string{"example.com", "c.example.com", "b.c.example.com", "a.b.c.example.com"},
		},
		{
			"sub.example.co.uk",
			[]string{"example.co.uk", "sub.example.co.uk"},
		},
	}

	for _, test := range tests {
		result := awd.getParentDomains(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("getParentDomains(%s) returned %d domains; expected %d", test.input, len(result), len(test.expected))
			continue
		}

		for i := range result {
			if result[i] != test.expected[i] {
				t.Errorf("getParentDomains(%s)[%d] = %s; expected %s", test.input, i, result[i], test.expected[i])
			}
		}
	}
}

func TestAutoWildcardCaching(t *testing.T) {
	awd := NewAutoWildcardDetector(nil)

	// Test that tested domains are cached
	domain := "example.com"
	awd.testedDomains[domain] = true
	awd.wildcardCache[domain] = []string{"1.2.3.4", "5.6.7.8"}

	// Should return cached result
	result := awd.detectWildcard(domain, nil)
	if len(result) != 2 {
		t.Errorf("Expected cached result with 2 IPs, got %d", len(result))
	}
}

func TestGetStats(t *testing.T) {
	awd := NewAutoWildcardDetector(nil)

	// Set some test values
	awd.wildcardDomainsCount = 5
	awd.filteredCount = 15

	wildcardDomains, filteredHosts := awd.GetStats()

	if wildcardDomains != 5 {
		t.Errorf("Expected 5 wildcard domains, got %d", wildcardDomains)
	}

	if filteredHosts != 15 {
		t.Errorf("Expected 15 filtered hosts, got %d", filteredHosts)
	}
}
