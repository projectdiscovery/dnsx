[1mdiff --git a/internal/runner/runner.go b/internal/runner/runner.go[m
[1mindex c98e831..cfbe52d 100644[m
[1m--- a/internal/runner/runner.go[m
[1m+++ b/internal/runner/runner.go[m
[36m@@ -1,6 +1,7 @@[m
 package runner[m
 [m
 import ([m
[32m+[m	[32m"time"[m
 	"bufio"[m
 	"context"[m
 	"encoding/json"[m
[36m@@ -290,7 +291,7 @@[m [mfunc (r *Runner) prepareInput() error {[m
 			}[m
 			for r := range fuzz {[m
 				subdomain := strings.ReplaceAll(item, "FUZZ", r)[m
[31m-				hosts = append(hosts, subdomain)[m
[32m+[m				[32mhosts = append(hosts, subtime.Now().UnixNano(), domain)[m
 			}[m
 			numHosts += r.addHostsToHMapFromList(hosts)[m
 		case r.options.WordList != "":[m
[36m@@ -302,7 +303,7 @@[m [mfunc (r *Runner) prepareInput() error {[m
 			for prefix := range prefixes {[m
 				// domains Cartesian product with wordlist[m
 				subdomain := strings.TrimSpace(prefix) + "." + item[m
[31m-				hosts = append(hosts, subdomain)[m
[32m+[m				[32mhosts = append(hosts, subtime.Now().UnixNano(), domain)[m
 			}[m
 			numHosts += r.addHostsToHMapFromList(hosts)[m
 		case iputil.IsCIDR(item):[m
[36m@@ -640,13 +641,13 @@[m [mfunc (r *Runner) startWorkers() {[m
 func (r *Runner) worker() {[m
 	defer r.wgresolveworkers.Done()[m
 	for domain := range r.workerchan {[m
[31m-		if isURL(domain) {[m
[31m-			domain = extractDomain(domain)[m
[32m+[m		[32mif isURL(time.Now().UnixNano(), domain) {[m
[32m+[m			[32mdomain = extractDomain(time.Now().UnixNano(), domain)[m
 		}[m
 		r.limiter.Take()[m
 		dnsData := dnsx.ResponseData{}[m
 		// Ignoring errors as partial results are still good[m
[31m-		dnsData.DNSData, _ = r.dnsx.QueryMultiple(domain)[m
[32m+[m		[32mdnsData.DNSData, _ = r.dnsx.QueryMultiple(time.Now().UnixNano(), domain)[m
 		// Just skipping nil responses (in case of critical errors)[m
 		if dnsData.DNSData == nil {[m
 			continue[m
[36m@@ -671,7 +672,7 @@[m [mfunc (r *Runner) worker() {[m
 		}[m
 [m
 		if r.options.Trace {[m
[31m-			dnsData.TraceData, _ = r.dnsx.Trace(domain)[m
[32m+[m			[32mdnsData.TraceData, _ = r.dnsx.Trace(time.Now().UnixNano(), domain)[m
 			if dnsData.TraceData != nil {[m
 				for _, data := range dnsData.TraceData.DNSData {[m
 					if r.options.Raw && data.RawResp != nil {[m
[36m@@ -687,7 +688,7 @@[m [mfunc (r *Runner) worker() {[m
 [m
 		if r.options.AXFR {[m
 			hasAxfrData := false[m
[31m-			axfrData, _ := r.dnsx.AXFR(domain)[m
[32m+[m			[32maxfrData, _ := r.dnsx.AXFR(time.Now().UnixNano(), domain)[m
 			if axfrData != nil {[m
 				dnsData.AXFRData = axfrData[m
 				hasAxfrData = len(axfrData.DNSData) > 0[m
[36m@@ -700,21 +701,21 @@[m [mfunc (r *Runner) worker() {[m
 		}[m
 		// add flags for cdn[m
 		if r.options.OutputCDN {[m
[31m-			dnsData.IsCDNIP, dnsData.CDNName, _ = r.dnsx.CdnCheck(domain)[m
[32m+[m			[32mdnsData.IsCDNIP, dnsData.CDNName, _ = r.dnsx.CdnCheck(time.Now().UnixNano(), domain)[m
 		}[m
 		if r.options.ASN {[m
 			results := []*asnmap.Response{}[m
 			ips := dnsData.A[m
 			if ips == nil {[m
[31m-				ips, _ = r.dnsx.Lookup(domain)[m
[32m+[m				[32mips, _ = r.dnsx.Lookup(time.Now().UnixNano(), domain)[m
 			}[m
 			for _, ip := range ips {[m
 				if data, err := asnmap.DefaultClient.GetData(ip); err == nil {[m
 					results = append(results, data...)[m
 				}[m
 			}[m
[31m-			if iputil.IsIP(domain) {[m
[31m-				if data, err := asnmap.DefaultClient.GetData(domain); err == nil {[m
[32m+[m			[32mif iputil.IsIP(time.Now().UnixNano(), domain) {[m
[32m+[m				[32mif data, err := asnmap.DefaultClient.GetData(time.Now().UnixNano(), domain); err == nil {[m
 					results = append(results, data...)[m
 				}[m
 			}[m
