package dnsx

import (
	"testing"

	"github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

func TestFilterAnswerSectionOnly(t *testing.T) {
	tests := []struct {
		name          string
		setupDNSData  func() *retryabledns.DNSData
		expectedA     []string
		expectedAAAA  []string
		expectedCNAME []string
		expectedEmpty bool
	}{
		{
			name: "Filter out ADDITIONAL section A records",
			setupDNSData: func() *retryabledns.DNSData {
				msg := &dns.Msg{}
				msg.SetQuestion("anyinvaliddomain.projectdiscovery.io.", dns.TypeA)

				msg.Answer = []dns.RR{}

				msg.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 79449},
						Ns:  "g.root-servers.net.",
					},
				}

				msg.Extra = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 77741},
						A:   []byte{192, 112, 36, 4},
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 77741},
						A:   []byte{198, 97, 190, 53},
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 81186},
						A:   []byte{198, 41, 0, 4},
					},
				}

				dnsData := &retryabledns.DNSData{
					Host:    "anyinvaliddomain.projectdiscovery.io",
					RawResp: msg,
					A:       []string{"192.112.36.4", "198.97.190.53", "198.41.0.4"},
				}
				return dnsData
			},
			expectedA:     []string{},
			expectedEmpty: true,
		},
		{
			name: "Keep only ANSWER section A records",
			setupDNSData: func() *retryabledns.DNSData {
				msg := &dns.Msg{}
				msg.SetQuestion("projectdiscovery.io.", dns.TypeA)

				msg.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "projectdiscovery.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{93, 184, 216, 34},
					},
				}

				msg.Extra = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "ns.projectdiscovery.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
				}

				dnsData := &retryabledns.DNSData{
					Host:    "projectdiscovery.io",
					RawResp: msg,
					A:       []string{"93.184.216.34", "192.0.2.1"},
				}
				return dnsData
			},
			expectedA: []string{"93.184.216.34"},
		},
		{
			name: "Filter CNAME from ANSWER only",
			setupDNSData: func() *retryabledns.DNSData {
				msg := &dns.Msg{}
				msg.SetQuestion("www.projectdiscovery.io.", dns.TypeCNAME)

				msg.Answer = []dns.RR{
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: "www.projectdiscovery.io.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
						Target: "projectdiscovery.io.",
					},
				}

				msg.Extra = []dns.RR{
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: "alias.projectdiscovery.io.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
						Target: "other.projectdiscovery.io.",
					},
				}

				dnsData := &retryabledns.DNSData{
					Host:    "www.projectdiscovery.io",
					RawResp: msg,
					CNAME:   []string{"projectdiscovery.io", "other.projectdiscovery.io"},
				}
				return dnsData
			},
			expectedCNAME: []string{"projectdiscovery.io."},
		},
		{
			name: "Nil RawResp should not panic",
			setupDNSData: func() *retryabledns.DNSData {
				return &retryabledns.DNSData{
					Host:    "projectdiscovery.io",
					RawResp: nil,
					A:       []string{"93.184.216.34"},
				}
			},
			expectedA: []string{"93.184.216.34"},
		},
		{
			name: "Nil DNSData should not panic",
			setupDNSData: func() *retryabledns.DNSData {
				return nil
			},
			expectedEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsData := tt.setupDNSData()

			FilterAnswerSectionOnly(dnsData)

			if tt.expectedEmpty && dnsData == nil {
				return
			}

			require.NotNil(t, dnsData, "DNSData should not be nil")

			if len(tt.expectedA) > 0 || tt.expectedEmpty {
				require.ElementsMatch(t, tt.expectedA, dnsData.A, "A records should match expected")
			}

			if len(tt.expectedCNAME) > 0 {
				require.ElementsMatch(t, tt.expectedCNAME, dnsData.CNAME, "CNAME records should match expected")
			}

			if dnsData.RawResp != nil && len(dnsData.RawResp.Extra) > 0 && len(dnsData.RawResp.Answer) == 0 {
				require.Empty(t, dnsData.A, "A records should be empty when ANSWER section is empty")
			}
		})
	}
}
