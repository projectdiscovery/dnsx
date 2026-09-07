package dnsx

import (
	"strings"
	"testing"
)

// TestWave15TXTRecordQuoteUnescaping asserts quoted TXT record cleanup
func TestWave15TXTRecordQuoteUnescaping(t *testing.T) {
	unescapeTXT := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			return trimmed[1 : len(trimmed)-1]
		}
		return trimmed
	}

	sample := `"v=spf1 include:_spf.google.com ~all"`
	expected := "v=spf1 include:_spf.google.com ~all"
	actual := unescapeTXT(sample)

	if actual != expected {
		t.Errorf("expected unquoted TXT value %s, got %s", expected, actual)
	}

	unquoted := "v=DMARC1; p=reject;"
	if unescapeTXT(unquoted) != unquoted {
		t.Errorf("expected clean unquoted string to remain unchanged")
	}
}

// TestWave15SPFRecordSyntaxValidation tests SPF prefix detection
func TestWave15SPFRecordSyntaxValidation(t *testing.T) {
	isSPFRecord := func(txt string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1")
	}

	if !isSPFRecord("v=spf1 -all") {
		t.Errorf("expected SPF record detection to return true")
	}
	if isSPFRecord("google-site-verification=abcdef") {
		t.Errorf("expected non-SPF TXT record to return false")
	}
}
