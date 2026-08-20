package runner

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

func TestConfigureQueryOptions_QueryTypeAndExcludeType(t *testing.T) {
	t.Run("query type all with exclusions", func(t *testing.T) {
		options := &Options{
			QueryType:   goflags.StringSlice{"all"},
			ExcludeType: goflags.StringSlice{"ptr", "axfr", "any"},
		}
		options.configureQueryOptions()

		require.True(t, options.A)
		require.True(t, options.AAAA)
		require.True(t, options.CNAME)
		require.True(t, options.NS)
		require.True(t, options.TXT)
		require.True(t, options.SRV)
		require.True(t, options.MX)
		require.True(t, options.SOA)
		require.True(t, options.CAA)

		require.False(t, options.PTR)
		require.False(t, options.AXFR)
		require.False(t, options.ANY)
	})

	t.Run("specific query types", func(t *testing.T) {
		options := &Options{
			QueryType: goflags.StringSlice{"a", "cname", "txt"},
		}
		options.configureQueryOptions()

		require.True(t, options.A)
		require.True(t, options.CNAME)
		require.True(t, options.TXT)

		require.False(t, options.AAAA)
		require.False(t, options.NS)
		require.False(t, options.SRV)
		require.False(t, options.PTR)
		require.False(t, options.MX)
		require.False(t, options.SOA)
		require.False(t, options.AXFR)
		require.False(t, options.CAA)
		require.False(t, options.ANY)
	})

	t.Run("case-insensitive query types", func(t *testing.T) {
		options := &Options{
			QueryType: goflags.StringSlice{"A", "AAAA"},
		}
		options.configureQueryOptions()

		require.True(t, options.A)
		require.True(t, options.AAAA)

		require.False(t, options.CNAME)
		require.False(t, options.NS)
		require.False(t, options.TXT)
		require.False(t, options.SRV)
		require.False(t, options.PTR)
		require.False(t, options.MX)
		require.False(t, options.SOA)
		require.False(t, options.AXFR)
		require.False(t, options.CAA)
		require.False(t, options.ANY)
	})

	t.Run("legacy standalone flags compatibility", func(t *testing.T) {
		options := &Options{
			AAAA: true,
			MX:   true,
		}
		options.configureQueryOptions()

		require.True(t, options.AAAA)
		require.True(t, options.MX)

		require.False(t, options.A)
		require.False(t, options.CNAME)
		require.False(t, options.NS)
		require.False(t, options.TXT)
		require.False(t, options.SRV)
		require.False(t, options.PTR)
		require.False(t, options.SOA)
		require.False(t, options.AXFR)
		require.False(t, options.CAA)
		require.False(t, options.ANY)
	})

	t.Run("legacy query all recon flag", func(t *testing.T) {
		options := &Options{
			QueryAll: true,
		}
		options.configureQueryOptions()

		require.True(t, options.A)
		require.True(t, options.AAAA)
		require.True(t, options.CNAME)
		require.True(t, options.NS)
		require.True(t, options.TXT)
		require.True(t, options.SRV)
		require.True(t, options.PTR)
		require.True(t, options.MX)
		require.True(t, options.SOA)
		require.True(t, options.AXFR)
		require.True(t, options.CAA)
		require.False(t, options.ANY)
		require.True(t, options.Response)
	})
}

func TestFlagSet_QueryTypeAndExcludeTypeFlags(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		expected    map[string]bool
		notExpected map[string]bool
	}{
		{
			name: "short flags -q and -eq",
			args: []string{"-q", "all", "-eq", "ptr,axfr,any"},
			expected: map[string]bool{
				"a": true, "aaaa": true, "cname": true, "ns": true,
				"txt": true, "srv": true, "mx": true, "soa": true, "caa": true,
			},
			notExpected: map[string]bool{
				"ptr": true, "axfr": true, "any": true,
			},
		},
		{
			name: "long flags -query-type and -exclude-type",
			args: []string{"-query-type", "a,cname,txt"},
			expected: map[string]bool{
				"a": true, "cname": true, "txt": true,
			},
			notExpected: map[string]bool{
				"aaaa": true, "ns": true, "srv": true, "ptr": true,
				"mx": true, "soa": true, "axfr": true, "caa": true, "any": true,
			},
		},
		{
			name: "case insensitive flags",
			args: []string{"-q", "A,AAAA", "-eq", "AAAA"},
			expected: map[string]bool{
				"a": true,
			},
			notExpected: map[string]bool{
				"aaaa": true, "cname": true, "ns": true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &Options{}
			flagSet := goflags.NewFlagSet()
			flagSet.StringSliceVarP(&options.QueryType, "query-type", "q", nil, "dns query type", goflags.NormalizedStringSliceOptions)
			flagSet.StringSliceVarP(&options.ExcludeType, "exclude-type", "eq", nil, "dns query type to exclude", goflags.NormalizedStringSliceOptions)

			err := flagSet.CommandLine.Parse(tc.args)
			require.NoError(t, err)

			options.configureQueryOptions()

			queryMap := map[string]bool{
				"a": options.A, "aaaa": options.AAAA, "cname": options.CNAME,
				"ns": options.NS, "txt": options.TXT, "srv": options.SRV,
				"ptr": options.PTR, "mx": options.MX, "soa": options.SOA,
				"axfr": options.AXFR, "caa": options.CAA, "any": options.ANY,
			}

			for k := range tc.expected {
				require.Truef(t, queryMap[k], "expected query type %s to be true", k)
			}
			for k := range tc.notExpected {
				require.Falsef(t, queryMap[k], "expected query type %s to be false", k)
			}
		})
	}
}
