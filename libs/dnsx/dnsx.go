package dnsx

import (
	"errors"
	"math"
	"net"

	miekgdns "github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// DNSX is structure to perform dns lookups
type DNSX struct {
	dnsClient *retryabledns.Client
	Options   *Options
}

// Options contains configuration options
type Options struct {
	BaseResolvers     []string
	MaxRetries        int
	QuestionTypes     []uint16
	Trace             bool
	TraceMaxRecursion int
}

// DefaultOptions contains the default configuration options
var DefaultOptions = Options{
	BaseResolvers:     DefaultResolvers,
	MaxRetries:        5,
	QuestionTypes:     []uint16{miekgdns.TypeA},
	TraceMaxRecursion: math.MaxUint16,
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// New creates a dns resolver
func New(options Options) (*DNSX, error) {
	dnsClient := retryabledns.New(options.BaseResolvers, options.MaxRetries)

	return &DNSX{dnsClient: dnsClient, Options: &options}, nil
}

// Lookup performs a DNS A question and returns corresponding IPs
func (d *DNSX) Lookup(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}

	dnsdata, err := d.dnsClient.Resolve(hostname)
	if err != nil {
		return nil, err
	}

	if dnsdata == nil || len(dnsdata.A) == 0 {
		return []string{}, errors.New("no ips found")
	}

	return dnsdata.A, nil
}

// QueryOne performs a DNS question of a specified type and returns raw responses
func (d *DNSX) QueryOne(hostname string) (*retryabledns.DNSData, error) {
	return d.dnsClient.Query(hostname, d.Options.QuestionTypes[0])
}

// QueryMultiple performs a DNS question of the specified types and returns raw responses
func (d *DNSX) QueryMultiple(hostname string) (*retryabledns.DNSData, error) {
	return d.dnsClient.QueryMultiple(hostname, d.Options.QuestionTypes)
}

// Trace performs a DNS trace of the specified types and returns raw responses
func (d *DNSX) Trace(hostname string) (*retryabledns.TraceData, error) {
	return d.dnsClient.Trace(hostname, d.Options.QuestionTypes[0], d.Options.TraceMaxRecursion)
}
