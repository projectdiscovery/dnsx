package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/retryabledns"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/stretchr/testify/require"
)

func TestRunner_singleDomain_prepareInput(t *testing.T) {
	options := &Options{
		Domains: "one.one.one.one",
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	r := Runner{
		options: options,
		hm:      hm,
	}
	// call the prepareInput
	err = r.prepareInput()
	require.Nil(t, err, "failed to prepare input")
	expected := []string{"one.one.one.one"}
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func TestRunner_domainWildCard_prepareInput(t *testing.T) {
	options := &Options{
		Domains:  "projectdiscovery.io",
		WordList: "jenkins,beta",
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	r := Runner{
		options: options,
		hm:      hm,
	}
	// call the prepareInput
	err = r.prepareInput()
	if isUnauthorizedError(err) {
		t.Skip()
	}
	require.Nil(t, err, "failed to prepare input")
	expected := []string{"jenkins.projectdiscovery.io", "beta.projectdiscovery.io"}
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func TestRunner_cidrInput_prepareInput(t *testing.T) {
	options := &Options{
		Domains: "173.0.84.0/30",
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	r := Runner{
		options: options,
		hm:      hm,
	}
	// call the prepareInput
	err = r.prepareInput()
	if isUnauthorizedError(err) {
		t.Skip()
	}
	require.Nil(t, err, "failed to prepare input")
	expected := []string{"173.0.84.0", "173.0.84.1", "173.0.84.2", "173.0.84.3"}
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func TestRunner_asnInput_prepareInput(t *testing.T) {
	options := &Options{
		Domains: "AS14421",
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	r := Runner{
		options: options,
		hm:      hm,
	}
	// call the prepareInput
	err = r.prepareInput()
	if isUnauthorizedError(err) {
		t.Skip()
	}
	require.Nil(t, err, "failed to prepare input")
	expectedOutputFile := "tests/AS14421.txt"
	// read the expected IPs from the file
	fileContent, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, "could not read the expectedOutputFile file")
	expected := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func isUnauthorizedError(err error) bool {
	return err != nil && stringsutil.ContainsAny(err.Error(), "unauthorized")
}

// TestAutoWildcardMutualExclusion verifies that combining -aw and -wd is
// rejected by the dedicated validation helper.
func TestAutoWildcardMutualExclusion(t *testing.T) {
	// both flags set → error
	opts := &Options{AutoWildcard: true, WildcardDomain: "example.com"}
	require.Error(t, opts.validateAutoWildcardFlags(), "expected error when both -aw and -wd are set")

	// only AutoWildcard → ok
	opts = &Options{AutoWildcard: true}
	require.NoError(t, opts.validateAutoWildcardFlags())

	// only WildcardDomain → ok
	opts = &Options{WildcardDomain: "example.com"}
	require.NoError(t, opts.validateAutoWildcardFlags())

	// neither → ok
	opts = &Options{}
	require.NoError(t, opts.validateAutoWildcardFlags())
}

// TestAutoWildcardStoresData verifies that storeDNSData persists DNS records
// into the hybrid map, which is the mechanism the worker uses when
// AutoWildcard (or WildcardDomain) is enabled.
func TestAutoWildcardStoresData(t *testing.T) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	defer hm.Close()

	r := &Runner{
		options: &Options{AutoWildcard: true},
		hm:      hm,
	}

	dnsData := &retryabledns.DNSData{
		Host: "test.example.com",
		A:    []string{"1.2.3.4"},
	}

	err = r.storeDNSData(dnsData)
	require.Nil(t, err, "storeDNSData should succeed")

	stored, ok := hm.Get("test.example.com")
	require.True(t, ok, "DNS data should be stored in hm when AutoWildcard is set")
	require.NotEmpty(t, stored, "stored data must not be empty")
}

// TestIsWildcardParameterized verifies that wildcardHosts (the core of
// IsWildcard) uses the passed baseDomain parameter — not any global state —
// to build the set of domains to probe.
func TestIsWildcardParameterized(t *testing.T) {
	// single-level subdomain: only the baseDomain itself is probed
	hosts := wildcardHosts("sub.example.com", "example.com")
	require.Equal(t, []string{"example.com"}, hosts)

	// two-level subdomain: baseDomain + intermediate level probed
	hosts = wildcardHosts("deep.sub.example.com", "example.com")
	require.Equal(t, []string{"example.com", "sub.example.com"}, hosts)

	// different base domain entirely — must reflect the new baseDomain
	hosts = wildcardHosts("sub.other.com", "other.com")
	require.Equal(t, []string{"other.com"}, hosts)

	// multi-part TLD (e.g. .co.uk)
	hosts = wildcardHosts("sub.example.co.uk", "example.co.uk")
	require.Equal(t, []string{"example.co.uk"}, hosts)

	// two-level under multi-part TLD
	hosts = wildcardHosts("deep.sub.example.co.uk", "example.co.uk")
	require.Equal(t, []string{"example.co.uk", "sub.example.co.uk"}, hosts)
}

func TestRunner_fileInput_prepareInput(t *testing.T) {
	options := &Options{
		Hosts: "tests/file_input.txt",
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.Nil(t, err, "could not create hybrid map")
	r := Runner{
		options: options,
		hm:      hm,
	}
	// call the prepareInput
	err = r.prepareInput()
	if isUnauthorizedError(err) {
		t.Skip()
	}
	require.Nil(t, err, "failed to prepare input")
	expected := []string{"one.one.one.one", "example.com"}
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func TestRunner_InputWorkerStream(t *testing.T) {
	options := &Options{
		Hosts: "tests/stream_input.txt",
	}
	r := Runner{
		options:    options,
		workerchan: make(chan string),
	}
	go r.InputWorkerStream()
	var got []string
	for c := range r.workerchan {
		got = append(got, c)
	}
	expected := []string{"173.0.84.0", "173.0.84.1", "173.0.84.2", "173.0.84.3", "one.one.one.one"}
	// read the expected IPs from the file
	fileContent, err := os.ReadFile("tests/AS14421.txt")
	require.Nil(t, err, "could not read the expectedOutputFile file")
	expected = append(expected, strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")...)
	require.ElementsMatch(t, expected, got, "could not match expected output")
}
