<h1 align="center">
  <img src="static/dnsx-logo.png" alt="dnsx" width="200px">
  <br>
</h1>

<h4 align="center">A fast and multi-purpose DNS toolkit designed for running DNS queries</h4>

<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/dnsx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/dnsx"></a>
<a href="https://github.com/projectdiscovery/dnsx/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/dnsx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/dnsx"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-instructions">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-dnsx">Running `dnsx`</a> •
  <a href="#wildcard-filtering">Wildcard</a> •
  <a href="#-notes">Notes</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


---

`dnsx` is a fast and multi-purpose DNS toolkit designed for running various probes through the [retryabledns](https://github.com/projectdiscovery/retryabledns) library. It supports multiple DNS queries, user supplied resolvers, DNS wildcard filtering like [shuffledns](https://github.com/projectdiscovery/shuffledns) etc.


# Features

<h1 align="left">
  <img src="https://github.com/projectdiscovery/dnsx/assets/8293321/73fe69a0-15b8-4b54-bacc-e201edd90103" alt="dnsx" width="700px"></a>
  <br>
</h1>


 - Simple and Handy utility to query DNS records.
 - **A, AAAA, CNAME, PTR, NS, MX, TXT, SRV, SOA** query support
 - DNS **Resolution** / **Brute-force** support
 - Custom **resolver** input support
 - Multiple resolver format **(TCP/UDP/DOH/DOT)** support
 - **stdin** and **stdout** support
 - Automatic **wildcard** handling support

# Installation Instructions


`dnsx` requires **go1.21** to install successfully. Run the following command to install the latest version: 

```sh
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

# Usage

```sh
dnsx -h
```

This will display help for the tool. Here are all the switches it supports.

```console
INPUT:
   -l, -list string      list of sub(domains)/hosts to resolve (file or stdin)
   -d, -domain string    list of domain to bruteforce (file or comma separated or stdin)
   -w, -wordlist string  list of words to bruteforce (file or comma separated or stdin)

QUERY:
   -a                       query A record (default)
   -aaaa                    query AAAA record
   -cname                   query CNAME record
   -ns                      query NS record
   -txt                     query TXT record
   -srv                     query SRV record
   -ptr                     query PTR record
   -mx                      query MX record
   -soa                     query SOA record
   -any                     query ANY record
   -axfr                    query AXFR
   -caa                     query CAA record
   -recon                   query all the dns records (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)
   -e, -exclude-type value  dns query type to exclude (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa) (default none)

FILTER:
   -re, -resp          display dns response
   -ro, -resp-only     display dns response only
   -rc, -rcode string  filter result by dns status code (eg. -rcode noerror,servfail,refused)

PROBE:
   -cdn  display cdn name
   -asn  display host asn information

RATE-LIMIT:
   -t, -threads int      number of concurrent threads to use (default 100)
   -rl, -rate-limit int  number of dns request/second to make (disabled as default) (default -1)

UPDATE:
   -up, -update                 update dnsx to latest version
   -duc, -disable-update-check  disable automatic dnsx update check

OUTPUT:
   -o, -output string  file to write output
   -j, -json           write output in JSONL(ines) format
   -omit-raw, -or      omit raw dns response from jsonl output

DEBUG:
   -hc, -health-check  run diagnostic check up
   -silent             display only results in the output
   -v, -verbose        display verbose output
   -raw, -debug        display raw dns response
   -stats              display stats of the running scan
   -version            display version of dnsx
   -nc, -no-color      disable color in output

OPTIMIZATION:
   -retry int                number of dns attempts to make (must be at least 1) (default 2)
   -hf, -hostsfile           use system host file
   -trace                    perform dns tracing
   -trace-max-recursion int  Max recursion for dns trace (default 32767)
   -resume                   resume existing scan
   -stream                   stream mode (wordlist, wildcard, stats and stop/resume will be disabled)

CONFIGURATIONS:
   -auth                         configure projectdiscovery cloud (pdcp) api key (default true)
   -r, -resolver string          list of resolvers to use (file or comma separated)
   -wt, -wildcard-threshold int  wildcard filter threshold (default 5)
   -wd, -wildcard-domain string  domain name for wildcard filtering (other flags will be ignored - only json output is supported)
```

## Running dnsx

### DNS Resolving

Filter active hostnames from the list of passive subdomains, obtained from various sources:

```console
subfinder -silent -d hackerone.com | dnsx -silent

a.ns.hackerone.com
www.hackerone.com
api.hackerone.com
docs.hackerone.com
mta-sts.managed.hackerone.com
mta-sts.hackerone.com
resources.hackerone.com
b.ns.hackerone.com
mta-sts.forwarding.hackerone.com
events.hackerone.com
support.hackerone.com
```

Print **A** records for the given list of subdomains:

```console
subfinder -silent -d hackerone.com | dnsx -silent -a -resp

www.hackerone.com [104.16.100.52]
www.hackerone.com [104.16.99.52]
hackerone.com [104.16.99.52]
hackerone.com [104.16.100.52]
api.hackerone.com [104.16.99.52]
api.hackerone.com [104.16.100.52]
mta-sts.forwarding.hackerone.com [185.199.108.153]
mta-sts.forwarding.hackerone.com [185.199.109.153]
mta-sts.forwarding.hackerone.com [185.199.110.153]
mta-sts.forwarding.hackerone.com [185.199.111.153]
a.ns.hackerone.com [162.159.0.31]
resources.hackerone.com [52.60.160.16]
resources.hackerone.com [3.98.63.202]
resources.hackerone.com [52.60.165.183]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [185.199.110.153]
mta-sts.hackerone.com [185.199.111.153]
mta-sts.hackerone.com [185.199.109.153]
mta-sts.hackerone.com [185.199.108.153]
gslink.hackerone.com [13.35.210.17]
gslink.hackerone.com [13.35.210.38]
gslink.hackerone.com [13.35.210.83]
gslink.hackerone.com [13.35.210.19]
b.ns.hackerone.com [162.159.1.31]
docs.hackerone.com [185.199.109.153]
docs.hackerone.com [185.199.110.153]
docs.hackerone.com [185.199.111.153]
docs.hackerone.com [185.199.108.153]
support.hackerone.com [104.16.51.111]
support.hackerone.com [104.16.53.111]
mta-sts.managed.hackerone.com [185.199.108.153]
mta-sts.managed.hackerone.com [185.199.109.153]
mta-sts.managed.hackerone.com [185.199.110.153]
mta-sts.managed.hackerone.com [185.199.111.153]
```

Extract **A** records for the given list of subdomains:

```console
subfinder -silent -d hackerone.com | dnsx -silent -a -resp-only

104.16.99.52
104.16.100.52
162.159.1.31
104.16.99.52
104.16.100.52
185.199.110.153
185.199.111.153
185.199.108.153
185.199.109.153
104.16.99.52
104.16.100.52
104.16.51.111
104.16.53.111
185.199.108.153
185.199.111.153
185.199.110.153
185.199.111.153
```

Extract **CNAME** records for the given list of subdomains:

```console
subfinder -silent -d hackerone.com | dnsx -silent -cname -resp

support.hackerone.com [hackerone.zendesk.com]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [hacker0x01.github.io]
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
events.hackerone.com [whitelabel.bigmarker.com]
```
Extract **ASN** records for the given list of subdomains:
```console
subfinder -silent -d hackerone.com | dnsx -silent  -asn

b.ns.hackerone.com [AS13335, CLOUDFLARENET, US]
a.ns.hackerone.com [AS13335, CLOUDFLARENET, US]
hackerone.com [AS13335, CLOUDFLARENET, US]
www.hackerone.com [AS13335, CLOUDFLARENET, US]
api.hackerone.com [AS13335, CLOUDFLARENET, US]
support.hackerone.com [AS13335, CLOUDFLARENET, US]
```

Probe using [dns status code](https://github.com/projectdiscovery/dnsx/wiki/RCODE-ID-VALUE-Mapping) on given list of (sub)domains:

```console
subfinder -silent -d hackerone.com | dnsx -silent -rcode noerror,servfail,refused

ns.hackerone.com [NOERROR]
a.ns.hackerone.com [NOERROR]
b.ns.hackerone.com [NOERROR]
support.hackerone.com [NOERROR]
resources.hackerone.com [NOERROR]
mta-sts.hackerone.com [NOERROR]
www.hackerone.com [NOERROR]
mta-sts.forwarding.hackerone.com [NOERROR]
docs.hackerone.com [NOERROR]
```

Extract subdomains from given network range using `PTR` query:

```console
echo 173.0.84.0/24 | dnsx -silent -resp-only -ptr

cors.api.paypal.com
trinityadminauth.paypal.com
cld-edge-origin-api.paypal.com
appmanagement.paypal.com
svcs.paypal.com
trinitypie-serv.paypal.com
ppn.paypal.com
pointofsale-new.paypal.com
pointofsale.paypal.com
slc-a-origin-pointofsale.paypal.com
fpdbs.paypal.com
```

Extract subdomains from given ASN using `PTR` query:
```console
echo AS17012 | dnsx -silent -resp-only -ptr 

apiagw-a.paypal.com
notify.paypal.com
adnormserv-slc-a.paypal.com
a.sandbox.paypal.com
apps2.paypal-labs.com
pilot-payflowpro.paypal.com
www.paypallabs.com
paypal-portal.com
micropayments.paypal-labs.com
minicart.paypal-labs.com
```
---------

### DNS Bruteforce

Bruteforce subdomains for given domain or list of domains using `d` and `w` flag:

```console
dnsx -silent -d facebook.com -w dns_worldlist.txt

blog.facebook.com
booking.facebook.com
api.facebook.com
analytics.facebook.com
beta.facebook.com
apollo.facebook.com
ads.facebook.com
box.facebook.com
alpha.facebook.com
apps.facebook.com
connect.facebook.com
c.facebook.com
careers.facebook.com
code.facebook.com
```

Bruteforce targeted subdomain using single or multiple keyword input, as `d` or `w` flag supports file or comma separated keyword inputs:

```console
dnsx -silent -d domains.txt -w jira,grafana,jenkins

grafana.1688.com
grafana.8x8.vc
grafana.airmap.com
grafana.aerius.nl
jenkins.1688.com
jenkins.airbnb.app
jenkins.airmap.com
jenkins.ahn.nl
jenkins.achmea.nl
jira.amocrm.com
jira.amexgbt.com
jira.amitree.com
jira.arrival.com
jira.atlassian.net
jira.atlassian.com
```

Values are accepted from **stdin** for all the input types (`-list`, `-domain`, `-wordlist`). The `-list` flag defaults to `stdin`, but the same can be achieved for other input types by adding a `-` (dash) as parameter:

```console
cat domains.txt | dnsx -silent -w jira,grafana,jenkins -d -

grafana.1688.com
grafana.8x8.vc
grafana.airmap.com
grafana.aerius.nl
jenkins.1688.com
jenkins.airbnb.app
jenkins.airmap.com
jenkins.ahn.nl
jenkins.achmea.nl
jira.amocrm.com
jira.amexgbt.com
jira.amitree.com
jira.arrival.com
jira.atlassian.net
jira.atlassian.com
```

#### DNS Bruteforce with Placeholder based wordlist

```bash
$ cat tld.txt

com
by
de
be
al
bi
cg
dj
bs
```

```console
dnsx -d google.FUZZ -w tld.txt -resp

      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  / 
 | (_| || | | |\__ \ /  \ 
  \__,_||_| |_||___//_/\_\ v1.1.2

      projectdiscovery.io

google.de [142.250.194.99] 
google.com [142.250.76.206] 
google.be [172.217.27.163] 
google.bs [142.251.42.35] 
google.bi [216.58.196.67] 
google.al [216.58.196.68] 
google.by [142.250.195.4] 
google.cg [142.250.183.131] 
google.dj [142.250.192.3] 
```

### Wildcard filtering

A special feature of `dnsx` is its ability to handle **multi-level DNS based wildcards**, and do it so with a very reduced number of DNS requests. Sometimes all the subdomains will resolve, which leads to lots of garbage in the output. The way `dnsx` handles this is by keeping track of how many subdomains point to an IP and if the count of the subdomains increase beyond a certain threshold, it will check for wildcards on all the levels of the hosts for that IP iteratively.

```console
dnsx -l subdomain_list.txt -wd airbnb.com -o output.txt
```

---------

### Dnsx as a library

It's possible to use the library directly in your golang programs. The following code snippets is an example of use in golang programs. Please refer to [here](https://pkg.go.dev/github.com/projectdiscovery/dnsx@v1.1.0/libs/dnsx) for detailed package configuration and usage.

```go
package main

import (
	"fmt"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func main() {
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	// DNS A question and returns corresponding IPs
	result, err := dnsClient.Lookup("hackerone.com")
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	for idx, msg := range result {
		fmt.Printf("%d: %s\n", idx+1, msg)
	}

	// Query
	rawResp, err := dnsClient.QueryOne("hackerone.com")
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Printf("rawResp: %v\n", rawResp)

	jsonStr, err := rawResp.JSON()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Println(jsonStr)

	return
}
```

# 📋 Notes

- As default, `dnsx` checks for **A** record.
- As default `dnsx` uses Google, Cloudflare, Quad9 [resolver](https://github.com/projectdiscovery/dnsx/blob/43af78839e237ea8cbafe571df1ab0d6cbe7f445/libs/dnsx/dnsx.go#L31).
- Custom resolver list can be loaded using the `r` flag.
- Domain name (`wd`) input is mandatory for wildcard elimination.
- DNS record flag can not be used when using wildcard filtering.
- DNS resolution (`l`) and DNS brute-forcing (`w`) can't be used together.
- VPN operators tend to filter high DNS/UDP traffic, therefore the tool might experience packets loss (eg. [Mullvad VPN](https://github.com/projectdiscovery/dnsx/issues/221))

`dnsx` is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
