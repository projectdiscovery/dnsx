package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
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
	err = r.prepareInput()
	if err != nil && strings.Contains(err.Error(), "unauthorized") {
		t.Skip("skipping: ASN API key not configured")
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
	require.Nil(t, err, "failed to prepare input")
	expected := []string{"one.one.one.one", "example.com"}
	got := []string{}
	r.hm.Scan(func(k, v []byte) error {
		got = append(got, string(k))
		return nil
	})
	require.ElementsMatch(t, expected, got, "could not match expected output")
}

func TestRunner_hostsInput_prepareInput(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.NoError(t, err)
		r := Runner{options: &Options{Hosts: "tests/file_input.txt"}, hm: hm}
		require.NoError(t, r.prepareInput())
		got := scanHMap(t, r.hm)
		require.ElementsMatch(t, []string{"one.one.one.one", "example.com"}, got)
	})

	t.Run("stdin", func(t *testing.T) {
		tmp, err := os.CreateTemp("", "dnsx-stdin-test")
		require.NoError(t, err)
		defer os.Remove(tmp.Name())
		_, err = tmp.WriteString("one.one.one.one\nexample.com\n")
		require.NoError(t, err)
		tmp.Close()

		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.NoError(t, err)
		r := Runner{options: &Options{Hosts: "-"}, hm: hm, tmpStdinFile: tmp.Name()}
		require.NoError(t, r.prepareInput())
		got := scanHMap(t, r.hm)
		require.ElementsMatch(t, []string{"one.one.one.one", "example.com"}, got)
	})

	t.Run("single inline host", func(t *testing.T) {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.NoError(t, err)
		r := Runner{options: &Options{Hosts: "one.one.one.one"}, hm: hm}
		require.NoError(t, r.prepareInput())
		got := scanHMap(t, r.hm)
		require.ElementsMatch(t, []string{"one.one.one.one"}, got)
	})

	t.Run("comma separated", func(t *testing.T) {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.NoError(t, err)
		r := Runner{options: &Options{Hosts: "one.one.one.one,example.com,cloudflare.com"}, hm: hm}
		require.NoError(t, r.prepareInput())
		got := scanHMap(t, r.hm)
		require.ElementsMatch(t, []string{"one.one.one.one", "example.com", "cloudflare.com"}, got)
	})

	t.Run("empty returns error", func(t *testing.T) {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.NoError(t, err)
		r := Runner{options: &Options{}, hm: hm}
		require.Error(t, r.prepareInput())
	})
}

func scanHMap(t *testing.T, hm *hybrid.HybridMap) []string {
	t.Helper()
	var items []string
	hm.Scan(func(k, v []byte) error {
		items = append(items, string(k))
		return nil
	})
	return items
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
