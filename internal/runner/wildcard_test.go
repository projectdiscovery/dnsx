package runner

import "testing"

func TestWildcardBaseDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{input: "www.example.com", expected: "example.com"},
		{input: "Example.COM", expected: "example.com"},
		{input: "a.b.example.co.uk", expected: "example.co.uk"},
		{input: "example.co.uk", expected: "example.co.uk"},
		{input: "localhost", expected: ""},
		{input: "192.168.0.1", expected: ""},
		{input: "example.com.", expected: "example.com"},
	}

	for _, tt := range tests {
		if got := wildcardBaseDomain(tt.input); got != tt.expected {
			t.Errorf("wildcardBaseDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
