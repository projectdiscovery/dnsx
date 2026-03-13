package runner

import (
	"testing"
	"github.com/stretchr/testify/require"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"foo.bar.co.uk", "bar.co.uk"},
		{"api.service.com.au", "service.com.au"},
		{"foo.example.com.", "example.com"},
		{"https://sub.example.com/path", "example.com"},
		{"http://foo.bar.co.uk:8080", "bar.co.uk"},
	}

	for _, tc := range tests {
		got := extractDomain(tc.input)
		require.Equal(t, tc.expected, got, "input: %s", tc.input)
	}
}
