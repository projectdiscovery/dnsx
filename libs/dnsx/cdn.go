package dnsx

import (
	"net"

	"github.com/projectdiscovery/retryabledns"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
)

// CdnCheck verifies if the given domain/ip is part of Cdn/Waf/Cloud ranges
func (d *DNSX) CdnCheck(input string) (matched bool, value string, itemType string, err error) {
	if d.cdn == nil {
		return false, "", "", errorutil.New("cdn client not initialized")
	}
	if iputil.IsIP(input) {
		ipAddr := net.ParseIP(input)
		matched, value, itemType, err = d.cdn.Check(ipAddr)
		return
	}

	return d.cdn.CheckDomainWithFallback(input)
}

// CdnCheck verifies if the given dnsResponse is part of Cdn/Waf/Cloud ranges
func (d *DNSX) CdnCheckRespData(dnsdata *retryabledns.DNSData) (matched bool, value string, itemType string, err error) {
	if d.cdn == nil {
		return false, "", "", errorutil.New("cdn client not initialized")
	}
	return d.cdn.CheckDNSResponse(dnsdata)
}
