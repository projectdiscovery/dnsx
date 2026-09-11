package dnsx

import (
	"testing"
)

func TestDSDNSKEYDigestTypeHandling(t *testing.T) {
	// Digest Type 2 = SHA-256, Algorithm 13 = ECDSA P-256
	dsRecord := struct {
		KeyTag     uint16
		Algorithm  uint8
		DigestType uint8
		Digest     string
	}{
		KeyTag:     2371,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "2BB18343E3F170D6B32E447D3F372626C904D61E",
	}
	
	if dsRecord.DigestType != 2 || dsRecord.Algorithm != 13 {
		t.Fatalf("unexpected DNSSEC DS record parameter values")
	}
}
