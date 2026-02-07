package runner

import (
	"strings"

	"github.com/projectdiscovery/retryabledns"
	"github.com/rs/xid"
)

type wildcardFingerprintKind uint8

const (
	wildcardFingerprintNone wildcardFingerprintKind = iota
	wildcardFingerprintIP
	wildcardFingerprintCNAME
)

type wildcardFingerprint struct {
	kind   wildcardFingerprintKind
	values map[string]struct{}
}

type wildcardQueryer interface {
	QueryMultiple(host string) (*retryabledns.DNSData, error)
}

const autoWildcardCheckCount = 3

// IsWildcard checks if a host is wildcard
func (r *Runner) IsWildcard(host string) bool {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	subdomainPart := strings.TrimSuffix(host, "."+r.options.WildcardDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, r.options.WildcardDomain)

	if len(subdomainTokens) > 0 {
		for i := 1; i < len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + r.options.WildcardDomain
			hosts = append(hosts, newhost)
		}
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		r.wildcardscachemutex.Lock()
		listip, ok := r.wildcardscache[h]
		r.wildcardscachemutex.Unlock()
		if !ok {
			in, err := r.dnsx.QueryOne(xid.New().String() + "." + h)
			if err != nil || in == nil {
				continue
			}
			listip = in.A
			r.wildcardscachemutex.Lock()
			r.wildcardscache[h] = in.A
			r.wildcardscachemutex.Unlock()
		}

		// Get all the records and add them to the wildcard map
		for _, A := range listip {
			if _, ok := wildcards[A]; !ok {
				wildcards[A] = struct{}{}
			}
		}
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true
		}
	}

	return false
}

func (r *Runner) autoWildcardFingerprint(root string) wildcardFingerprint {
	root = strings.ToLower(strings.TrimSuffix(root, "."))
	if root == "" {
		return wildcardFingerprint{}
	}

	r.autoWildcardMutex.Lock()
	fp, ok := r.autoWildcardCache[root]
	r.autoWildcardMutex.Unlock()
	if ok {
		return fp
	}

	fp = r.detectAutoWildcardFingerprint(root)

	r.autoWildcardMutex.Lock()
	if r.autoWildcardCache == nil {
		r.autoWildcardCache = make(map[string]wildcardFingerprint)
	}
	r.autoWildcardCache[root] = fp
	r.autoWildcardMutex.Unlock()

	return fp
}

func (r *Runner) detectAutoWildcardFingerprint(root string) wildcardFingerprint {
	resolver := r.autoWildcardResolver
	if resolver == nil {
		resolver = r.dnsx
	}
	if resolver == nil {
		return wildcardFingerprint{}
	}

	var base wildcardFingerprint
	for i := 0; i < autoWildcardCheckCount; i++ {
		host := xid.New().String() + "." + root
		in, err := resolver.QueryMultiple(host)
		if err != nil || in == nil {
			return wildcardFingerprint{}
		}

		fp := fingerprintFromDNSData(in)
		if fp.kind == wildcardFingerprintNone {
			return wildcardFingerprint{}
		}

		if i == 0 {
			base = fp
			continue
		}
		if !fingerprintsEqual(base, fp) {
			return wildcardFingerprint{}
		}
	}
	return base
}

func (r *Runner) matchesAutoWildcard(root string, dnsData *retryabledns.DNSData) bool {
	if dnsData == nil {
		return false
	}
	fp := r.autoWildcardFingerprint(root)
	if fp.kind == wildcardFingerprintNone {
		return false
	}
	dataFP := fingerprintFromDNSData(dnsData)
	if dataFP.kind == wildcardFingerprintNone || dataFP.kind != fp.kind {
		return false
	}
	return fingerprintsEqual(fp, dataFP)
}

func fingerprintFromDNSData(data *retryabledns.DNSData) wildcardFingerprint {
	if data == nil {
		return wildcardFingerprint{}
	}
	if len(data.CNAME) > 0 {
		return wildcardFingerprint{
			kind:   wildcardFingerprintCNAME,
			values: sliceToSet(data.CNAME),
		}
	}
	if len(data.A) == 0 && len(data.AAAA) == 0 {
		return wildcardFingerprint{}
	}
	values := sliceToSet(data.A)
	for _, item := range data.AAAA {
		values[item] = struct{}{}
	}
	return wildcardFingerprint{
		kind:   wildcardFingerprintIP,
		values: values,
	}
}

func sliceToSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

func fingerprintsEqual(a, b wildcardFingerprint) bool {
	if a.kind != b.kind {
		return false
	}
	if len(a.values) != len(b.values) {
		return false
	}
	for item := range a.values {
		if _, ok := b.values[item]; !ok {
			return false
		}
	}
	return true
}
