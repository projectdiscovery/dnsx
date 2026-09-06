package runner

import (
	"crypto/rand"
	"encoding/hex"
	"net"
)

// WildcardDetector maintains baseline IP records from random subdomain probes
type WildcardDetector struct {
	KnownWildcardIPs map[string]bool
}

func NewWildcardDetector() *WildcardDetector {
	return &WildcardDetector{
		KnownWildcardIPs: make(map[string]bool),
	}
}

func (w *WildcardDetector) ProbeRandomSubdomain(domain string) ([]net.IP, error) {
	b := make([]byte, 8)
	rand.Read(b)
	randomHost := hex.EncodeToString(b) + "." + domain
	ips, err := net.LookupIP(randomHost)
	if err == nil {
		for _, ip := range ips {
			w.KnownWildcardIPs[ip.String()] = true
		}
	}
	return ips, err
}

func (w *WildcardDetector) IsWildcard(ip string) bool {
	return w.KnownWildcardIPs[ip]
}
