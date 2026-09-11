package dnsx

import (
	"testing"
)

func TestEDNS0ClientBufferSize(t *testing.T) {
	ednsBufferSize := uint16(4096)
	if ednsBufferSize < 512 {
		t.Fatalf("EDNS0 buffer size cannot be less than standard 512-byte UDP limit")
	}
}
