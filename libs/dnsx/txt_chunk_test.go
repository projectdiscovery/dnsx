package dnsx

import (
	"strings"
	"testing"
)

func TestTXTRecordChunkConcatenation(t *testing.T) {
	chunks := []string{"v=spf1 include:_spf.google.com ", "~all"}
	full := strings.Join(chunks, "")
	
	if !strings.Contains(full, "_spf.google.com") {
		t.Fatalf("expected concatenated TXT record to preserve spf rule, got %s", full)
	}
	if len(full) != 35 {
		t.Fatalf("unexpected TXT combined string length: %d", len(full))
	}
}
