package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/internal/testutils"
)

var dnsTestcases = map[string]testutils.TestCase{
	"DNS A Request":                 &dnsARequest{question: "projectdiscovery.io", expectedOutput: "projectdiscovery.io"},
	"DNS AAAA Request":              &dnsAAAARequest{question: "projectdiscovery.io", expectedOutput: "projectdiscovery.io"},
	"DNS Filter Additional Section": &dnsFilterAdditionalSection{question: "anyinvaliddomain.projectdiscovery.io", expectedOutput: ""},
}

type dnsARequest struct {
	question       string
	expectedOutput string
}

func (h *dnsARequest) Execute() error {
	handler := &dnshandler{
		answers: []answer{
			{question: h.question, questionType: dns.TypeA, values: []string{"1.2.3.4"}},
		},
	}
	srv := &dns.Server{
		Handler: handler,
		Addr:    "127.0.0.1:15000",
		Net:     "udp",
	}
	go srv.ListenAndServe() //nolint
	defer srv.Shutdown()    //nolint

	var extra []string
	extra = append(extra, "-r", "127.0.0.1:15000")
	extra = append(extra, "-a")

	results, err := testutils.RunDnsxAndGetResults(h.question, debug, extra...)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}

	if h.expectedOutput != "" && !strings.EqualFold(results[0], h.expectedOutput) {
		return errIncorrectResult(h.expectedOutput, results[0])
	}

	return nil
}

type dnsAAAARequest struct {
	question       string
	expectedOutput string
}

func (h *dnsAAAARequest) Execute() error {
	handler := &dnshandler{
		answers: []answer{
			{question: h.question, questionType: dns.TypeAAAA, values: []string{"2001:db8:3333:4444:5555:6666:7777:8888"}},
		},
	}
	srv := &dns.Server{
		Handler: handler,
		Addr:    "127.0.0.1:15000",
		Net:     "udp",
	}
	go srv.ListenAndServe() //nolint
	defer srv.Shutdown()    //nolint

	var extra []string
	extra = append(extra, "-r", "127.0.0.1:15000")
	extra = append(extra, "-aaaa")

	results, err := testutils.RunDnsxAndGetResults(h.question, debug, extra...)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}

	if h.expectedOutput != "" && !strings.EqualFold(results[0], h.expectedOutput) {
		return errIncorrectResult(h.expectedOutput, results[0])
	}

	return nil
}

type answer struct {
	question     string
	questionType uint16
	values       []string
}

type dnshandler struct {
	answers []answer
}

func (t *dnshandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	question := r.Question[0].Name
	question = strings.TrimSuffix(question, ".")
	questionType := r.Question[0].Qtype
	for _, answer := range t.answers {
		if strings.EqualFold(question, answer.question) && answer.questionType == questionType {
			resp := buildAnswer(r, answer)
			w.WriteMsg(resp) //nolint
		}
	}
}

func buildAnswer(r *dns.Msg, ans answer) *dns.Msg {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true
	switch ans.questionType {
	case dns.TypeA:
		for _, value := range ans.values {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(ans.question), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(value),
			})
		}
	case dns.TypeAAAA:
		for _, value := range ans.values {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns.Fqdn(ans.question), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(value),
			})
		}
	}
	return &msg
}

type dnsFilterAdditionalSection struct {
	question       string
	expectedOutput string
}

func (h *dnsFilterAdditionalSection) Execute() error {
	handler := &dnshandlerWithAdditional{
		question: h.question,
	}
	srv := &dns.Server{
		Handler: handler,
		Addr:    "127.0.0.1:15001",
		Net:     "udp",
	}
	go srv.ListenAndServe()
	defer srv.Shutdown()

	var extra []string
	extra = append(extra, "-r", "127.0.0.1:15001")
	extra = append(extra, "-a", "-resp", "-json")

	results, err := testutils.RunDnsxAndGetResults(h.question, debug, extra...)
	if err != nil {
		return err
	}

	if len(results) > 0 {
		for _, result := range results {
			if strings.Contains(result, "192.112.36.4") ||
				strings.Contains(result, "198.97.190.53") ||
				strings.Contains(result, "198.41.0.4") {
				return errIncorrectResult("(no root server IPs)", result)
			}
		}
	}

	return nil
}

type dnshandlerWithAdditional struct {
	question string
}

func (t *dnshandlerWithAdditional) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	question := r.Question[0].Name
	question = strings.TrimSuffix(question, ".")

	if !strings.EqualFold(question, t.question) {
		return
	}

	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	msg.Answer = []dns.RR{}

	msg.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 79449},
			Ns:  "g.root-servers.net.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 79449},
			Ns:  "h.root-servers.net.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 79449},
			Ns:  "a.root-servers.net.",
		},
	}

	msg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 77741},
			A:   net.ParseIP("192.112.36.4"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 77741},
			A:   net.ParseIP("198.97.190.53"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 81186},
			A:   net.ParseIP("198.41.0.4"),
		},
	}

	w.WriteMsg(&msg)
}
