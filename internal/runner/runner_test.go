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

func TestRunner_getWildcardDomainForHost(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		wildcardDomain string
		autoWildcard   bool
		expected       string
	}{
		{
			name:           "explicit wildcard domain takes precedence",
			host:           "sub.example.com",
			wildcardDomain: "example.com",
			autoWildcard:   true,
			expected:       "example.com",
		},
		{
			name:           "auto-detect simple domain",
			host:           "sub.example.com",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "example.com",
		},
		{
			name:           "auto-detect multi-level subdomain",
			host:           "a.b.c.example.com",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "example.com",
		},
		{
			name:           "auto-detect with public suffix co.uk",
			host:           "sub.example.co.uk",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "example.co.uk",
		},
		{
			name:           "skip IP address",
			host:           "192.168.1.1",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "",
		},
		{
			name:           "skip IPv6 address",
			host:           "::1",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "",
		},
		{
			name:           "skip empty host",
			host:           "",
			wildcardDomain: "",
			autoWildcard:   true,
			expected:       "",
		},
		{
			name:           "feature disabled returns empty",
			host:           "sub.example.com",
			wildcardDomain: "",
			autoWildcard:   false,
			expected:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runner{
				options: &Options{
					WildcardDomain: tc.wildcardDomain,
					AutoWildcard:   tc.autoWildcard,
				},
			}
			got := r.getWildcardDomainForHost(tc.host)
			require.Equal(t, tc.expected, got)
		})
	}
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
