package runner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestRunner_withoutWildcardFilteringOutputsAllHosts(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{})
	require.ElementsMatch(t, []string{
		"example.com",
		"keep.example.com",
		"mixed.example.com",
		"wild1.example.com",
		"wild2.example.com",
		"shared.example.net",
		"keepv6.example.org",
		"v6wild1.example.org",
		"v6wild2.example.org",
	}, results)
}

func TestRunner_wildcardDomainFiltering(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{WildcardDomain: "example.com"})
	require.ElementsMatch(t, []string{
		"example.com",
		"keep.example.com",
		"shared.example.net",
	}, results)
	require.NotContains(t, results, "wild1.example.com")
	require.NotContains(t, results, "wild2.example.com")
}

func TestRunner_wildcardDomainFilteringNormalizesInput(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{WildcardDomain: "*.Example.COM."})
	require.ElementsMatch(t, []string{
		"example.com",
		"keep.example.com",
		"shared.example.net",
	}, results)
	require.NotContains(t, results, "wild1.example.com")
	require.NotContains(t, results, "wild2.example.com")
}

func TestNormalizeWildcardDomain(t *testing.T) {
	require.Equal(t, "example.com", normalizeWildcardDomain("*.Example.COM."))
	require.Equal(t, "", normalizeWildcardDomain("*."))
}

func TestRunner_autoWildcardFiltersByRoot(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{AutoWildcard: true})
	require.ElementsMatch(t, []string{
		"example.com",
		"keep.example.com",
		"shared.example.net",
		"keepv6.example.org",
	}, results)
	require.NotContains(t, results, "wild1.example.com")
	require.NotContains(t, results, "wild2.example.com")
	require.NotContains(t, results, "v6wild1.example.org")
	require.NotContains(t, results, "v6wild2.example.org")
}

func TestRunner_autoWildcardIgnoresWildcardThreshold(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{AutoWildcard: true, WildcardThreshold: 100})
	require.ElementsMatch(t, []string{
		"example.com",
		"keep.example.com",
		"shared.example.net",
		"keepv6.example.org",
	}, results)
	require.NotContains(t, results, "wild1.example.com")
	require.NotContains(t, results, "wild2.example.com")
	require.NotContains(t, results, "v6wild1.example.org")
	require.NotContains(t, results, "v6wild2.example.org")
}

func TestRunner_autoWildcardPreservesResponseOutput(t *testing.T) {
	results := runWildcardTestRunnerLines(t, &Options{AutoWildcard: true, Response: true, A: true})
	require.ElementsMatch(t, []string{
		"example.com [A] [9.9.9.9]",
		"keep.example.com [A] [1.1.1.1]",
		"shared.example.net [A] [2.2.2.2]",
	}, results)
}

func TestRunner_autoWildcardAAAAOnly(t *testing.T) {
	results := runWildcardTestRunner(t, &Options{AutoWildcard: true, A: false, AAAA: true})
	require.ElementsMatch(t, []string{"keepv6.example.org"}, results)
}

func TestRunner_autoWildcardCNAMEOnlyPreservesOutput(t *testing.T) {
	resolver, shutdown := startCNAMEWildcardTestDNSServer(t)
	defer shutdown()

	results := runWildcardTestRunnerLinesWithResolver(t, resolver, []string{
		"keep.example.com",
		"wild1.example.com",
		"wild2.example.com",
	}, &Options{AutoWildcard: true, Response: true, CNAME: true})

	require.ElementsMatch(t, []string{
		"keep.example.com [CNAME] [keep-target.example.com]",
	}, results)
}

func TestWildcardLookupAdapterInvokesStatsCallback(t *testing.T) {
	resolver, shutdown := startWildcardTestDNSServer(t)
	defer shutdown()

	options := dnsx.DefaultOptions
	options.BaseResolvers = []string{resolver}
	client, err := dnsx.New(options)
	require.NoError(t, err)

	limiter := ratelimit.NewUnlimited(context.Background())
	var calls atomic.Int32
	_, _, aAdapter, _, _, _, err := newWildcardResolvers(client, limiter, func() {
		calls.Add(1)
	})
	require.NoError(t, err)

	answers, err := aAdapter.lookup("keep.example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1"}, answers)
	require.EqualValues(t, 1, calls.Load())
}

func runWildcardTestRunner(t *testing.T, options *Options) []string {
	output := runWildcardTestRunnerOutput(t, options)
	return strings.Fields(output)
}

func runWildcardTestRunnerLines(t *testing.T, options *Options) []string {
	output := runWildcardTestRunnerOutput(t, options)
	return splitOutputLines(output)
}

func runWildcardTestRunnerLinesWithResolver(t *testing.T, resolver string, hosts []string, options *Options) []string {
	output := runWildcardTestRunnerOutputWithResolver(t, resolver, hosts, options)
	return splitOutputLines(output)
}

func splitOutputLines(output string) []string {
	parts := strings.Split(strings.TrimSpace(output), "\n")
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			lines = append(lines, part)
		}
	}
	return lines
}

func runWildcardTestRunnerOutput(t *testing.T, options *Options) string {
	t.Helper()

	resolver, shutdown := startWildcardTestDNSServer(t)
	defer shutdown()

	return runWildcardTestRunnerOutputWithResolver(t, resolver, defaultWildcardTestHosts(), options)
}

func runWildcardTestRunnerOutputWithResolver(t *testing.T, resolver string, hosts []string, options *Options) string {
	t.Helper()

	tempDir := t.TempDir()
	hostsFile := filepath.Join(tempDir, "hosts.txt")
	outputFile := filepath.Join(tempDir, "output.txt")

	err := os.WriteFile(hostsFile, []byte(strings.Join(hosts, "\n")), 0644)
	require.NoError(t, err)

	testOptions := &Options{
		Hosts:             hostsFile,
		OutputFile:        outputFile,
		Resolvers:         resolver,
		Threads:           4,
		Retries:           1,
		Timeout:           time.Second,
		Silent:            true,
		NoColor:           true,
		WildcardThreshold: 2,
		A:                 true,
		AAAA:              true,
	}

	if options != nil {
		testOptions.AutoWildcard = options.AutoWildcard
		testOptions.WildcardDomain = options.WildcardDomain
		if options.WildcardThreshold != 0 {
			testOptions.WildcardThreshold = options.WildcardThreshold
		}
		if options.A || options.AAAA || options.CNAME || options.Response || options.ResponseOnly || options.JSON {
			testOptions.A = options.A
			testOptions.AAAA = options.AAAA
			testOptions.CNAME = options.CNAME
			testOptions.Response = options.Response
			testOptions.ResponseOnly = options.ResponseOnly
			testOptions.JSON = options.JSON
		}
	}

	runner, err := New(testOptions)
	require.NoError(t, err)
	defer runner.Close()

	err = runner.Run()
	require.NoError(t, err)

	output, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	return string(output)
}

func defaultWildcardTestHosts() []string {
	return []string{
		"example.com",
		"keep.example.com",
		"mixed.example.com",
		"wild1.example.com",
		"wild2.example.com",
		"shared.example.net",
		"keepv6.example.org",
		"v6wild1.example.org",
		"v6wild2.example.org",
	}
}

func startWildcardTestDNSServer(t *testing.T) (string, func()) {
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
			for _, record := range wildcardTestARecords(question) {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(record),
				})
			}
		case dns.TypeAAAA:
			for _, record := range wildcardTestAAAARecords(question) {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP(record),
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

func startCNAMEWildcardTestDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		question := strings.TrimSuffix(r.Question[0].Name, ".")
		switch r.Question[0].Qtype {
		case dns.TypeCNAME:
			for _, target := range cnameWildcardTargets(question) {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: dns.Fqdn(target),
				})
			}
		case dns.TypeA:
			for _, record := range cnameWildcardARecords(question) {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(record),
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

func wildcardTestARecords(question string) []string {
	records := map[string][]string{
		"example.com":        {"9.9.9.9"},
		"keep.example.com":   {"1.1.1.1"},
		"mixed.example.com":  {"2.2.2.2", "8.8.8.8"},
		"wild1.example.com":  {"2.2.2.2"},
		"wild2.example.com":  {"2.2.2.2"},
		"shared.example.net": {"2.2.2.2"},
	}
	if answer, ok := records[question]; ok {
		return answer
	}
	if strings.HasSuffix(question, ".example.com") {
		return []string{"2.2.2.2"}
	}
	return nil
}

func wildcardTestAAAARecords(question string) []string {
	records := map[string][]string{
		"keepv6.example.org":  {"2001:db8::2"},
		"v6wild1.example.org": {"2001:db8::1"},
		"v6wild2.example.org": {"2001:db8::1"},
	}
	if answer, ok := records[question]; ok {
		return answer
	}
	if strings.HasSuffix(question, ".example.org") {
		return []string{"2001:db8::1"}
	}
	return nil
}

func cnameWildcardTargets(question string) []string {
	targets := map[string][]string{
		"keep.example.com":  {"keep-target.example.com"},
		"wild1.example.com": {"wildcard-target.example.com"},
		"wild2.example.com": {"wildcard-target.example.com"},
	}
	return targets[question]
}

func cnameWildcardARecords(question string) []string {
	records := map[string][]string{
		"keep.example.com":  {"1.1.1.1"},
		"wild1.example.com": {"2.2.2.2"},
		"wild2.example.com": {"2.2.2.2"},
	}
	if answer, ok := records[question]; ok {
		return answer
	}
	if strings.HasSuffix(question, ".example.com") {
		return []string{"2.2.2.2"}
	}
	return nil
}
