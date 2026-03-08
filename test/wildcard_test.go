package main

import (
    "testing"
    "github.com/projectdiscovery/dnsx"
)

// Test function to check the wildcard detection
func TestCheckWildcard(t *testing.T) {
    tests := []struct {
        domain string
        expected bool
    }{
        {"example.com", true},
        {"nonwildcard.com", false},
    }

    for _, tt := range tests {
        t.Run(tt.domain, func(t *testing.T) {
            got := checkWildcard(tt.domain)
            if got != tt.expected {
                t.Errorf("checkWildcard() = %v, want %v", got, tt.expected)
            }
        })
    }
}
