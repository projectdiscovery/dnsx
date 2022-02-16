<h1 align="center">
  <img src="static/dnsx-logo.png" alt="dnsx" width="200px"></a>
  <br>
</h1>

<h4 align="center">Fast and multi-purpose DNS toolkit allow to run multiple DNS queries.</h4>

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
  <a href="#running-dnsx">Running dnsx</a> •
  <a href="#wildcard-filtering">Wildcard</a> •
  <a href="#-notes">Notes</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


---


**dnsx** is a fast and multi-purpose DNS toolkit allow to run multiple probes using [retryabledns](https://github.com/projectdiscovery/retryabledns) library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers, additionally supports DNS wildcard filtering like [shuffledns](https://github.com/projectdiscovery/shuffledns).


# Features

<h1 align="left">
  <img src="static/dnsx-run.png" alt="dnsx" width="700px"></a>
  <br>
</h1>


 - Simple and Handy utility to query DNS records.
 - **A, AAAA, CNAME, PTR, NS, MX, TXT, SOA** query support
 - DNS **Resolution** support
 - DNS **Brute-force** support
 - DNS **Status** code probe support
 - DNS **Tracing** support
 - Automatic **wildcard** handling support
 - **stdin** and **stdout** support

# Installation Instructions


dnsx requires **go1.17** to install successfully. Run the following command to get the repo -

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
   -a      query A record (default)
   -aaaa   query AAAA record
   -cname  query CNAME record
   -ns     query NS record
   -txt    query TXT record
   -ptr    query PTR record
   -mx     query MX record
   -soa    query SOA record

FILTERS:
   -resp               display dns response
   -resp-only          display dns response only
   -rcode, -rc string  filter result by dns status code (eg. -rcode noerror,servfail,refused)

RATE-LIMIT:
   -t, -c int            number of concurrent threads to use (default 100)
   -rl, -rate-limit int  number of dns request/second to make (disabled as default) (default -1)

OUTPUT:
   -o, -output string  file to write output
   -json               write output in JSONL(ines) format

DEBUG:
   -silent       display only results in the output
   -v, -verbose  display verbose output
   -raw, -debug  display raw dns response
   -stats        display stats of the running scan
   -version      display version of dnsx

OPTIMIZATION:
   -retry int                number of dns retries to make (default 2)
   -hf, -hostsfile           use system host file
   -trace                    perform dns tracing
   -trace-max-recursion int  Max recursion for dns trace (default 32767)
   -flush-interval int       flush interval of output file (default 10)
   -resume                   resume existing scan

CONFIGURATIONS:
   -r, -resolver string          list of resolvers to use (file or comma separated)
   -wt, -wildcard-threshold int  wildcard filter threshold (default 5)
   -wd, -wildcard-domain string  domain name for wildcard filtering (other flags will be ignored)
```

## Running dnsx

### DNS Resolving

**dnsx** can be used to filter active hostnames from the list of passive subdomains obtained from various sources, for example:-

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

**dnsx** can be used to print **A** records for the given list of subdomains, for example:-

```console
subfinder -silent -d hackerone.com | dnsx -silent -a -cname -resp

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
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
a.ns.hackerone.com [162.159.0.31]
resources.hackerone.com [52.60.160.16]
resources.hackerone.com [3.98.63.202]
resources.hackerone.com [52.60.165.183]
resources.hackerone.com [read.uberflip.com]
resources.hackerone.com [nlb-ext-traefik-ca-central-1-d39d611502919b07.elb.ca-central-1.amazonaws.com]
mta-sts.hackerone.com [185.199.110.153]
mta-sts.hackerone.com [185.199.111.153]
mta-sts.hackerone.com [185.199.109.153]
mta-sts.hackerone.com [185.199.108.153]
mta-sts.hackerone.com [hacker0x01.github.io]
gslink.hackerone.com [13.35.210.17]
gslink.hackerone.com [13.35.210.38]
gslink.hackerone.com [13.35.210.83]
gslink.hackerone.com [13.35.210.19]
gslink.hackerone.com [d3rxkn2g2bbsjp.cloudfront.net]
b.ns.hackerone.com [162.159.1.31]
docs.hackerone.com [185.199.109.153]
docs.hackerone.com [185.199.110.153]
docs.hackerone.com [185.199.111.153]
docs.hackerone.com [185.199.108.153]
docs.hackerone.com [hacker0x01.github.io]
support.hackerone.com [104.16.51.111]
support.hackerone.com [104.16.53.111]
support.hackerone.com [hackerone.zendesk.com]
mta-sts.managed.hackerone.com [185.199.108.153]
mta-sts.managed.hackerone.com [185.199.109.153]
mta-sts.managed.hackerone.com [185.199.110.153]
mta-sts.managed.hackerone.com [185.199.111.153]
mta-sts.managed.hackerone.com [hacker0x01.github.io]
```


**dnsx** can be used to extract **A** records for the given list of subdomains, for example:-

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

**dnsx** can be used to extract **CNAME** records for the given list of subdomains, for example:-

```console
subfinder -silent -d hackerone.com | dnsx -silent -cname -resp

support.hackerone.com [hackerone.zendesk.com]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [hacker0x01.github.io]
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
events.hackerone.com [whitelabel.bigmarker.com]
```

**dnsx** can be used to probe by given [dns status code](https://github.com/projectdiscovery/dnsx/wiki/RCODE-ID-VALUE-Mapping) on given list of sub(domains), for example:-

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

**dnsx** can be used to extract subdomains from given network range using `PTR` query, for example:-

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

---------

### DNS Bruteforce

**dnsx** can be used to bruteforce subdomains for given domain or list of domains using `d` and `w` flag.

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

**dnsx** can be used to bruteforce targeted subdomain using single or multiple keyword input, as `d` or `w` flag supports file or comma separated keyword inputs.

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

**dnsx** support **stdin** input for all the input flags (`list`,`domain`,`wordlist`), as default `l` flag is supported for `stdin`, other input flag can be used by specifying the flag input with dash (`-`).

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

### Wildcard filtering

A special feature of **dnsx** is its ability to handle **multi-level DNS based wildcards** and do it so with very less number of DNS requests. Sometimes all the subdomains will resolve which will lead to lots of garbage in the results. The way **dnsx** handles this is it will keep track of how many subdomains point to an IP and if the count of the Subdomains increase beyond a certain small threshold, it will check for wildcard on all the levels of the hosts for that IP iteratively.

```console
dnsx -l subdomain_list.txt -wd airbnb.com -o output.txt
```

# 📋 Notes

- As default, **dnsx** checks for **A** record.
- As default dnsx uses Google, Cloudflare, Quad9 [resolver](https://github.com/projectdiscovery/dnsx/blob/43af78839e237ea8cbafe571df1ab0d6cbe7f445/libs/dnsx/dnsx.go#L31).
- Custom resolver list can be used using `r` flag.
- Domain name (`wd`) input is mandatory for wildcard elimination.
- DNS record flag can not be used when using wildcard filtering.
- DNS resolution (`l`) and DNS Bruteforcing (`w`) can't be used together.

dnsx is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
