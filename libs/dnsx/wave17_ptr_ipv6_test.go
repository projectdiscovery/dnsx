package dnsx

import (
	"net"
	"strings"
	"testing"
)

func BuildIPv6ReversePTR(ip net.IP) (string, bool) {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return "", false
	}

	var nibbles []string
	for i := len(ip16) - 1; i >= 0; i-- {
		b := ip16[i]
		low := b & 0x0F
		high := (b >> 4) & 0x0F
		nibbles = append(nibbles, strings.ToLower(string("0123456789abcdef"[low])))
		nibbles = append(nibbles, strings.ToLower(string("0123456789abcdef"[high])))
	}

	return strings.Join(nibbles, ".") + ".ip6.arpa.", true
}

func TestWave17IPv6ReversePTR(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	ptr, ok := BuildIPv6ReversePTR(ipv6)
	if !ok {
		t.Fatalf("expected valid IPv6 PTR generation")
	}

	expectedPrefix := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if ptr != expectedPrefix {
		t.Errorf("BuildIPv6ReversePTR() = %s, expected %s", ptr, expectedPrefix)
	}

	// Test rejection of IPv4
	ipv4 := net.ParseIP("192.168.1.1")
	_, v4Ok := BuildIPv6ReversePTR(ipv4)
	if v4Ok {
		t.Errorf("expected IPv4 address to be rejected in IPv6 PTR generator")
	}
}
