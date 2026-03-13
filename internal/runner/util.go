package runner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/net/publicsuffix"
)

const (
	stdinMarker = "-"
	Comma       = ","
	NewLine     = "\n"
)

func linesInFile(fileName string) ([]string, error) {
	result := []string{}
	f, err := fileutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	for line := range f {
		result = append(result, line)
	}
	return result, nil
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func extractDomain(URL string) string {
	var host string
	if !strings.Contains(URL, "://") && !isURL(URL) {
		host = strings.TrimSuffix(URL, ".")
	} else {
		u, err := url.Parse(URL)
		if err != nil {
			return ""
		}
		host = strings.TrimSuffix(u.Hostname(), ".")
	}

	// Use public suffix list for accurate eTLD+1 extraction
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// fallback to last two parts if publicsuffix fails
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}
	return domain
}

func prepareResolver(resolver string) string {
	resolver = strings.TrimSpace(resolver)
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}
	return resolver
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}
