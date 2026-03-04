package runner

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/retryabledns"
)

// fakeDNSX implements a stubbed QueryOne
type fakeDNSX struct {
	responses map[string][]string
}

func (f *fakeDNSX) QueryOne(host string) (*retryabledns.DNSData, error) {
	// strip random prefix to domain
	parts := strings.SplitN(host, ".", 2)
	domain := parts[len(parts)-1]
	if ips, ok := f.responses[domain]; ok {
		return &retryabledns.DNSData{A: ips}, nil
	}
	return &retryabledns.DNSData{A: []string{}}, nil
}

func TestWildcardDetection_Positive(t *testing.T) {
	r := &Runner{dnsx: &fakeDNSX{responses: map[string][]string{"example.com": {"1.1.1.1"}}}}
	det := NewAutoWildcardDetector(r)
	ips, err := det.WildcardIPsForDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ips["1.1.1.1"]; !ok {
		t.Errorf("expected wildcard IP 1.1.1.1, got %v", ips)
	}
}

func TestWildcardDetection_Negative(t *testing.T) {
	// simulate first probe returns, second empty => no wildcard
	calls := 0
	r := &Runner{dnsx: &fakeDNSX{responses: map[string][]string{"example.com": {"2.2.2.2"}}}}
	det := NewAutoWildcardDetector(r)
	// override QueryOne to return only on first call
	runnerQuery := det.runner.dnsx.QueryOne
	dummy := &fakeDNSX{responses: make(map[string][]string)}
	det.runner.dnsx = &fakeDNSX{responses: map[string][]string{"example.com": {"2.2.2.2"}}}
	// simulate next calls returning empty by clearing responses
	orig := det.runner.dnsx.(*fakeDNSX).responses
	det.runner.dnsx.(*fakeDNSX).responses = map[string][]string{"example.com": {"2.2.2.2"}}
	// first call ok, then clear
	det.runner.dnsx.(*fakeDNSX).responses = map[string][]string{}}
	ips, err := det.WildcardIPsForDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ips != nil && len(ips) != 0 {
		t.Errorf("expected no wildcard, got %v", ips)
	}
	// restore
	det.runner.dnsx = r.dnsx
}
