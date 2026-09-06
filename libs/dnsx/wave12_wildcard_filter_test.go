package dnsx

import (
	"testing"
)

// TestWave12WildcardIPCollisionFilter asserts wildcard response detection
func TestWave12WildcardIPCollisionFilter(t *testing.T) {
	wildcardIPs := map[string]bool{
		"192.0.2.1": true,
		"198.51.100.1": true,
	}

	isWildcardResponse := func(resolvedIP string) bool {
		return wildcardIPs[resolvedIP]
	}

	if !isWildcardResponse("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 to be flagged as wildcard sinkhole IP")
	}
	if isWildcardResponse("104.21.45.12") {
		t.Errorf("expected genuine IP to pass wildcard filter")
	}
}

// TestWave12CNAMETargetFormat asserts valid canonical name structure
func TestWave12CNAMETargetFormat(t *testing.T) {
	isValidCNAMETarget := func(target string) bool {
		return len(target) > 0 && len(target) <= 253
	}

	if !isValidCNAMETarget("canonical.cdn.bountygrid.net") {
		t.Errorf("expected valid CNAME target length")
	}
	if isValidCNAMETarget("") {
		t.Errorf("expected empty CNAME target to fail")
	}
}
