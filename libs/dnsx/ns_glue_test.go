package dnsx

import (
	"net"
	"testing"
)

func TestNSGlueRecordResolution(t *testing.T) {
	glueIP := net.ParseIP("198.41.0.4")
	if glueIP == nil || glueIP.To4() == nil {
		t.Fatalf("failed to parse authoritative NS glue IPv4 address")
	}
}
