package runner

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

func TestAutoWildcardDetectionAndMatch(t *testing.T) {
	r := &Runner{
		options:              &Options{AutoWildcard: true},
		autoWildcardCache:    make(map[string]wildcardFingerprint),
		autoWildcardResolver: &fakeResolver{},
	}

	fp := r.autoWildcardFingerprint("wild.test")
	require.Equal(t, wildcardFingerprintIP, fp.kind)
	require.ElementsMatch(t, []string{"1.2.3.4"}, setKeys(fp.values))

	wildData, err := r.autoWildcardResolver.QueryMultiple("random.wild.test")
	require.NoError(t, err)
	require.True(t, r.matchesAutoWildcard("wild.test", wildData))

	realData, err := r.autoWildcardResolver.QueryMultiple("real.wild.test")
	require.NoError(t, err)
	require.False(t, r.matchesAutoWildcard("wild.test", realData))

	fp = r.autoWildcardFingerprint("nowild.test")
	require.Equal(t, wildcardFingerprintNone, fp.kind)
}

type fakeResolver struct{}

func (f *fakeResolver) QueryMultiple(host string) (*retryabledns.DNSData, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case host == "real.wild.test":
		return &retryabledns.DNSData{Host: host, A: []string{"9.9.9.9"}}, nil
	case host == "wild.test":
		return &retryabledns.DNSData{Host: host, A: []string{"5.5.5.5"}}, nil
	case strings.HasSuffix(host, ".wild.test"):
		return &retryabledns.DNSData{Host: host, A: []string{"1.2.3.4"}}, nil
	case host == "real.nowild.test":
		return &retryabledns.DNSData{Host: host, A: []string{"2.2.2.2"}}, nil
	case strings.HasSuffix(host, ".nowild.test"):
		return &retryabledns.DNSData{Host: host}, nil
	default:
		return &retryabledns.DNSData{Host: host}, nil
	}
}

func setKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
