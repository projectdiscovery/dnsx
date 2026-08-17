package dnsx

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestWildcardDetection_WildcardEnabledDomain tests detection on wildcard-enabled domains
func TestWildcardDetection_WildcardEnabledDomain(t *testing.T) {
	resolver, shutdown := startMockWildcardDNSServer(t)
	defer shutdown()

	options := DefaultOptions
	options.BaseResolvers = []string{resolver}
	options.Timeout = time.Second
	options.MaxRetries = 1

	client, err := New(options)
	require.NoError(t, err)

	// Probe randomized subdomains for wildcard detection
	probe1 := "rand-entropy-12345.wildcard.example.com"
	probe2 := "rand-entropy-67890.wildcard.example.com"

	resp1, err := client.QueryOne(probe1)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	require.Equal(t, []string{"2.2.2.2"}, resp1.A)

	resp2, err := client.QueryOne(probe2)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	require.Equal(t, []string{"2.2.2.2"}, resp2.A)

	// Verify both randomized subdomains return the same wildcard IP signature
	require.Equal(t, resp1.A, resp2.A)
}

// TestWildcardDetection_NonWildcardDomainPassthrough tests non-wildcard domain passthrough
func TestWildcardDetection_NonWildcardDomainPassthrough(t *testing.T) {
	resolver, shutdown := startMockWildcardDNSServer(t)
	defer shutdown()

	options := DefaultOptions
	options.BaseResolvers = []string{resolver}
	options.Timeout = time.Second
	options.MaxRetries = 1

	client, err := New(options)
	require.NoError(t, err)

	// Probe randomized subdomain on non-wildcard domain returns NXDOMAIN / no A records
	probe := "rand-entropy-99999.static.example.org"
	resp, err := client.QueryOne(probe)
	require.NoError(t, err)
	require.True(t, resp == nil || resp.StatusCodeRaw == dns.RcodeNameError || len(resp.A) == 0)

	// Legitimate host on non-wildcard domain resolves normally
	validHost := "valid.static.example.org"
	validResp, err := client.QueryOne(validHost)
	require.NoError(t, err)
	require.NotNil(t, validResp)
	require.Equal(t, []string{"1.2.3.4"}, validResp.A)
}

// TestWildcardDetection_MultiDomainInputHandling tests handling multiple domains simultaneously
func TestWildcardDetection_MultiDomainInputHandling(t *testing.T) {
	resolver, shutdown := startMockWildcardDNSServer(t)
	defer shutdown()

	options := DefaultOptions
	options.BaseResolvers = []string{resolver}
	options.Timeout = time.Second
	options.MaxRetries = 1

	client, err := New(options)
	require.NoError(t, err)

	domains := []struct {
		domain     string
		isWildcard bool
		wildcardIP string
	}{
		{domain: "wildcard.example.com", isWildcard: true, wildcardIP: "2.2.2.2"},
		{domain: "static.example.org", isWildcard: false, wildcardIP: ""},
		{domain: "another-wildcard.net", isWildcard: true, wildcardIP: "3.3.3.3"},
	}

	for _, d := range domains {
		probe := "rand-entropy-test." + d.domain
		resp, err := client.QueryOne(probe)
		require.NoError(t, err)

		if d.isWildcard {
			require.NotNil(t, resp, "expected probe response for wildcard domain %s", d.domain)
			require.Equal(t, []string{d.wildcardIP}, resp.A)
		} else {
			require.True(t, resp == nil || resp.StatusCodeRaw == dns.RcodeNameError || len(resp.A) == 0,
				"expected no A records for non-wildcard domain probe %s", d.domain)
		}
	}
}

// TestWildcardDetection_CNAMEWildcardSignature tests wildcard CNAME signature detection
func TestWildcardDetection_CNAMEWildcardSignature(t *testing.T) {
	resolver, shutdown := startMockWildcardDNSServer(t)
	defer shutdown()

	options := DefaultOptions
	options.BaseResolvers = []string{resolver}
	options.QuestionTypes = []uint16{dns.TypeCNAME}
	options.Timeout = time.Second
	options.MaxRetries = 1

	client, err := New(options)
	require.NoError(t, err)

	probe1 := "rand-entropy-111.cname-wildcard.com"
	probe2 := "rand-entropy-222.cname-wildcard.com"

	resp1, err := client.QueryOne(probe1)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	require.Equal(t, []string{"wildcard-target.cname-wildcard.com"}, resp1.CNAME)

	resp2, err := client.QueryOne(probe2)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	require.Equal(t, []string{"wildcard-target.cname-wildcard.com"}, resp2.CNAME)
}

func startMockWildcardDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		question := strings.TrimSuffix(r.Question[0].Name, ".")
		switch r.Question[0].Qtype {
		case dns.TypeA:
			if strings.HasSuffix(question, ".wildcard.example.com") {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("2.2.2.2"),
				})
			} else if strings.HasSuffix(question, ".another-wildcard.net") {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("3.3.3.3"),
				})
			} else if question == "valid.static.example.org" {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("1.2.3.4"),
				})
			}
		case dns.TypeCNAME:
			if strings.HasSuffix(question, ".cname-wildcard.com") {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: dns.Fqdn("wildcard-target.cname-wildcard.com"),
				})
			}
		}

		if len(msg.Answer) == 0 {
			msg.Rcode = dns.RcodeNameError
		}

		_ = w.WriteMsg(msg)
	})}

	go func() {
		_ = server.ActivateAndServe()
	}()

	return packetConn.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	}
}
