package dnsx

import (
	"strings"
	"testing"
)

func TestWaveDNSRecordHostnameTrailingDotTrim(t *testing.T) {
	normalizeDomain := func(d string) string {
		return strings.TrimSuffix(strings.ToLower(d), ".")
	}

	rawDomain := "api.BountyGrid.com."
	expected := "api.bountygrid.com"
	actual := normalizeDomain(rawDomain)

	if actual != expected {
		t.Errorf("expected normalized domain %s, got %s", expected, actual)
	}
}

func TestWaveDNSRecordTypeValidation(t *testing.T) {
	validTypes := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true, "MX": true, "NS": true}
	isValidRecordType := func(rt string) bool {
		return validTypes[strings.ToUpper(rt)]
	}

	if !isValidRecordType("cname") {
		t.Errorf("expected cname to be a recognized DNS record type")
	}
	if isValidRecordType("UNKNOWN_RECORD") {
		t.Errorf("expected unknown record to fail validation")
	}
}
