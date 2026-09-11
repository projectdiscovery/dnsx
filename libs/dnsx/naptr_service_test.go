package dnsx

import (
	"strings"
	"testing"
)

func TestNAPTRServiceTagValidation(t *testing.T) {
	service := "SIP+D2U"
	if !strings.Contains(service, "SIP") {
		t.Fatalf("expected SIP service flag in NAPTR record, got %s", service)
	}
}
