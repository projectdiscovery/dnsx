package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
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

func TestOptimizeQuestionTypes(t *testing.T) {
	t.Run("keeps single address query when A and CNAME are selected", func(t *testing.T) {
		got := optimizeQuestionTypes([]uint16{dns.TypeA, dns.TypeCNAME})
		require.Equal(t, []uint16{dns.TypeA}, got)
	})

	t.Run("keeps single address query when AAAA and CNAME are selected", func(t *testing.T) {
		got := optimizeQuestionTypes([]uint16{dns.TypeAAAA, dns.TypeCNAME})
		require.Equal(t, []uint16{dns.TypeAAAA}, got)
	})

	t.Run("does not alter query set when more than two record types are selected", func(t *testing.T) {
		input := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME}
		got := optimizeQuestionTypes(input)
		require.Equal(t, input, got)
	})
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
