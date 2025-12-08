package dnsx

import (
	"errors"
	"fmt"
	"net"

	iputil "github.com/projectdiscovery/utils/ip"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (d *DNSX) CdnCheck(domain string) (bool, string, error) {
	if d.cdn == nil {
		return false, "", errors.New("cdn client not initialized")
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false, "", err
	}
	ipv4Ips := []net.IP{}
	// filter ipv4s for ips
	for _, ip := range ips {
		if iputil.IsIPv4(ip) {
			ipv4Ips = append(ipv4Ips, ip)
		}
	}
	if len(ipv4Ips) < 1 {
		return false, "", fmt.Errorf("no IPV4s found in lookup for %v", domain)
	}
	ipAddr := ipv4Ips[0].String()
	if !iputil.IsIP(ipAddr) {
		return false, "", fmt.Errorf("%s is not a valid ip", ipAddr)
	}
	return d.cdn.CheckCDN(net.ParseIP((ipAddr)))
}
