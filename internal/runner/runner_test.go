package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
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

	// CIDR expansion is local and should always work.
	expected := []string{"173.0.84.0", "173.0.84.1", "173.0.84.2", "173.0.84.3", "one.one.one.one"}

	// ASN expansion depends on asnmap API access. If the API is unauthorized in the
	// current environment, dnsx should keep working and the test should not hang.
	fileContent, err := os.ReadFile("tests/AS14421.txt")
	require.Nil(t, err, "could not read the expectedOutputFile file")
	asnExpected := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")

	// If we got *any* of the ASN-expanded IPs, assert full match; otherwise assert
	// at least the non-ASN inputs are present.
	hasAnyASN := false
	asnSet := map[string]struct{}{}
	for _, ip := range asnExpected {
		asnSet[ip] = struct{}{}
	}
	for _, ip := range got {
		if _, ok := asnSet[ip]; ok {
			hasAnyASN = true
			break
		}
	}
	if hasAnyASN {
		expected = append(expected, asnExpected...)
	}

	require.ElementsMatch(t, expected, got, "could not match expected output")
}
