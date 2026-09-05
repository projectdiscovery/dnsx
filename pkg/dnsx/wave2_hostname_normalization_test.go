package dnsx

import (
	"strings"
	"testing"
)

func TestWave2HostnameNormalization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"  sub.example.com  ", "sub.example.com"},
		{"api.example.com.", "api.example.com"},
		{"TEST.DOMAIN.ORG.", "test.domain.org"},
	}

	normalize := func(host string) string {
		h := strings.TrimSpace(strings.ToLower(host))
		return strings.TrimSuffix(h, ".")
	}

	for _, tc := range testCases {
		res := normalize(tc.input)
		if res != tc.expected {
			t.Errorf("normalize(%q) = %q; want %q", tc.input, res, tc.expected)
		}
	}
}

func TestWave2FQDNTrailingDotHandling(t *testing.T) {
	ensureFQDN := func(host string) string {
		h := strings.TrimSpace(host)
		if !strings.HasSuffix(h, ".") && len(h) > 0 {
			return h + "."
		}
		return h
	}

	if got := ensureFQDN("example.com"); got != "example.com." {
		t.Errorf("ensureFQDN("example.com") = %q; want "example.com."", got)
	}
	if got := ensureFQDN("example.com."); got != "example.com." {
		t.Errorf("ensureFQDN("example.com.") = %q; want "example.com."", got)
	}
}
