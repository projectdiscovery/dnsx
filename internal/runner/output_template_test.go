package runner

import (
	"io"
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasttemplate"
)

func TestBuildTemplateFields(t *testing.T) {
	dnsData := &dnsx.ResponseData{
		DNSData: &retryabledns.DNSData{
			Host:  "example.com",
			A:     []string{"104.20.23.154", "172.66.147.243"},
			AAAA:  []string{"2606:4700:10::6814:179a"},
			CNAME: []string{"alias.example.com"},
			MX:    []string{"10 mail.example.com"},
			TTL:   300,
		},
		CDNName: "cloudflare",
	}

	fields, err := buildTemplateFields(dnsData)
	require.NoError(t, err)

	require.Equal(t, "example.com", fields["host"])
	require.Equal(t, "104.20.23.154,172.66.147.243", fields["a"])
	require.Equal(t, "2606:4700:10::6814:179a", fields["aaaa"])
	require.Equal(t, "alias.example.com", fields["cname"])
	require.Equal(t, "10 mail.example.com", fields["mx"])
	require.Equal(t, "300", fields["ttl"])
	require.Equal(t, "cloudflare", fields["cdn-name"])
	// ip alias combines A and AAAA records
	require.Equal(t, "104.20.23.154,172.66.147.243,2606:4700:10::6814:179a", fields["ip"])
	// unset fields are absent
	require.Empty(t, fields["ns"])
}


func TestStringifyTemplateValue(t *testing.T) {
	require.Equal(t, "example.com", stringifyTemplateValue("example.com"))
	require.Equal(t, "1.1.1.1,2.2.2.2", stringifyTemplateValue([]any{"1.1.1.1", "2.2.2.2"}))
	require.Equal(t, "300", stringifyTemplateValue(float64(300)))
	require.Equal(t, "3.14", stringifyTemplateValue(3.14))
	require.Equal(t, "true", stringifyTemplateValue(true))
	require.Equal(t, "", stringifyTemplateValue(nil))
	// nested/object values fall back to their JSON representation
	require.Equal(t, `{"as-number":"AS123"}`, stringifyTemplateValue(map[string]any{"as-number": "AS123"}))
}

func TestOutputTemplateRendering(t *testing.T) {
	dnsData := &dnsx.ResponseData{
		DNSData: &retryabledns.DNSData{
			Host: "example.com",
			A:    []string{"104.20.23.154"},
		},
	}
	fields, err := buildTemplateFields(dnsData)
	require.NoError(t, err)

	tests := []struct {
		template string
		expected string
	}{
		{"{{host}} {{a}}", "example.com 104.20.23.154"},
		{"{{ip}} - {{host}}", "104.20.23.154 - example.com"},
		{"{{host}}|{{unknown}}|end", "example.com||end"}, // unknown tag -> empty
	}

	for _, tt := range tests {
		tmpl, err := fasttemplate.NewTemplate(tt.template, "{{", "}}")
		require.NoError(t, err)
		out := tmpl.ExecuteFuncString(func(w io.Writer, tag string) (int, error) {
			return w.Write([]byte(fields[tag]))
		})
		require.Equal(t, tt.expected, out)
	}
}
