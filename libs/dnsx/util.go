package dnsx

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// StringToRequestType conversion helper
func StringToRequestType(tp string) (rt uint16, err error) {
	tp = strings.TrimSpace(strings.ToUpper(tp))
	switch tp {
	case "A":
		rt = dns.TypeA
	case "NS":
		rt = dns.TypeNS
	case "CNAME":
		rt = dns.TypeCNAME
	case "SOA":
		rt = dns.TypeSOA
	case "PTR":
		rt = dns.TypePTR
	case "ANY":
		rt = dns.TypeANY
	case "MX":
		rt = dns.TypeMX
	case "TXT":
		rt = dns.TypeTXT
	case "SRV":
		rt = dns.TypeSRV
	case "AAAA":
		rt = dns.TypeAAAA
	default:
		rt = dns.TypeNone
		err = fmt.Errorf("incorrect type")
	}

	return
}

// FilterAnswerSectionOnly filters DNSData to only include records from the ANSWER section.
// This prevents false positives from AUTHORITY and ADDITIONAL sections (e.g., root DNS server IPs).
func FilterAnswerSectionOnly(dnsData *retryabledns.DNSData) {
	if dnsData == nil || dnsData.RawResp == nil {
		return
	}

	answerRecords := dnsData.RawResp.Answer
	if len(answerRecords) == 0 {
		dnsData.A = nil
		dnsData.AAAA = nil
		dnsData.CNAME = nil
		dnsData.MX = nil
		dnsData.PTR = nil
		dnsData.SOA = nil
		dnsData.NS = nil
		dnsData.TXT = nil
		dnsData.SRV = nil
		dnsData.CAA = nil
		dnsData.AllRecords = nil
		return
	}

	var aRecords []string
	var aaaaRecords []string
	var cnameRecords []string
	var mxRecords []string
	var ptrRecords []string
	var soaRecords []retryabledns.SOA
	var nsRecords []string
	var txtRecords []string
	var srvRecords []string
	var caaRecords []string

	for _, rr := range answerRecords {
		switch v := rr.(type) {
		case *dns.A:
			aRecords = append(aRecords, v.A.String())
		case *dns.AAAA:
			aaaaRecords = append(aaaaRecords, v.AAAA.String())
		case *dns.CNAME:
			cnameRecords = append(cnameRecords, strings.ToLower(v.Target))
		case *dns.MX:
			mxRecords = append(mxRecords, strings.ToLower(v.Mx))
		case *dns.PTR:
			ptrRecords = append(ptrRecords, strings.ToLower(v.Ptr))
		case *dns.SOA:
			soaRecords = append(soaRecords, retryabledns.SOA{
				NS:     strings.ToLower(v.Ns),
				Mbox:   strings.ToLower(v.Mbox),
				Serial: v.Serial,
			})
		case *dns.NS:
			nsRecords = append(nsRecords, strings.ToLower(v.Ns))
		case *dns.TXT:
			txtRecords = append(txtRecords, v.Txt...)
		case *dns.SRV:
			srvRecords = append(srvRecords, strings.ToLower(v.Target))
		case *dns.CAA:
			caaRecords = append(caaRecords, strings.ToLower(v.Value))
		}
	}

	dnsData.A = aRecords
	dnsData.AAAA = aaaaRecords
	dnsData.CNAME = cnameRecords
	dnsData.MX = mxRecords
	dnsData.PTR = ptrRecords
	dnsData.SOA = soaRecords
	dnsData.NS = nsRecords
	dnsData.TXT = txtRecords
	dnsData.SRV = srvRecords
	dnsData.CAA = caaRecords

	allRecords := []string{}
	allRecords = append(allRecords, dnsData.A...)
	allRecords = append(allRecords, dnsData.AAAA...)
	allRecords = append(allRecords, dnsData.CNAME...)
	allRecords = append(allRecords, dnsData.MX...)
	allRecords = append(allRecords, dnsData.PTR...)
	allRecords = append(allRecords, dnsData.NS...)
	allRecords = append(allRecords, dnsData.TXT...)
	allRecords = append(allRecords, dnsData.SRV...)
	allRecords = append(allRecords, dnsData.CAA...)
	dnsData.AllRecords = allRecords
}
