package runner

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
)

// buildTemplateFields flattens a ResponseData into a map of template variables
// keyed by their JSON field names (e.g. host, a, aaaa, cname, ns, ...). Slice
// values are comma-joined and scalar values are stringified so they can be
// substituted directly into an output template. A convenience "ip" alias holds
// the combined A and AAAA records.
func buildTemplateFields(dnsData *dnsx.ResponseData) (map[string]string, error) {
	jsonStr, err := dnsData.JSON()
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, err
	}

	fields := make(map[string]string, len(raw)+1)
	for k, v := range raw {
		fields[k] = stringifyTemplateValue(v)
	}

	// convenience alias: {{ip}} = A and AAAA records combined
	ips := make([]string, 0, 2)
	if a := fields["a"]; a != "" {
		ips = append(ips, a)
	}
	if aaaa := fields["aaaa"]; aaaa != "" {
		ips = append(ips, aaaa)
	}
	fields["ip"] = strings.Join(ips, ",")

	return fields, nil
}

// stringifyTemplateValue converts a decoded JSON value into its template
// string representation, joining slices with commas.
func stringifyTemplateValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, stringifyTemplateValue(item))
		}
		return strings.Join(parts, ",")
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return ""
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// outputTemplateRecord renders a single host record using the user-supplied
// output template and pushes the result to the output channel. Unknown or empty
// tags are rendered as empty strings.
func (r *Runner) outputTemplateRecord(dnsData *dnsx.ResponseData) {
	fields, err := buildTemplateFields(dnsData)
	if err != nil {
		gologger.Warning().Msgf("could not build template fields for %s: %s", dnsData.Host, err)
		return
	}

	out, err := r.outputTemplate.ExecuteFuncStringWithErr(func(w io.Writer, tag string) (int, error) {
		return w.Write([]byte(fields[tag]))
	})
	if err != nil {
		gologger.Warning().Msgf("could not render output template: %s", err)
		return
	}

	r.outputchan <- out
}
