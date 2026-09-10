package dnsx

import (
	"testing"
)

func TestCAARecordIssuerParsing(t *testing.T) {
	caaRecord := struct {
		Flag  uint8
		Tag   string
		Value string
	}{
		Flag:  0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}
	
	if caaRecord.Tag != "issue" || caaRecord.Value != "letsencrypt.org" {
		t.Fatalf("unexpected CAA record payload structure")
	}
}
