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
 - Supports **A, AAAA, CNAME, PTR, NS, MX, TXT, SOA**
 - Supports DNS Status Code probing
 - Supports DNS Tracing
 - Handles wildcard subdomains in automated way.
 - **Stdin** and **stdout** support to work with other tools.

# Usage

```sh
dnsx -h
```

This will display help for the tool. Here are all the switches it supports.

```console
INPUT:
   -l, -list string  File input with list of sub(domains)/hosts

QUERY:
   -a      Query A record (default)
   -aaaa   Query AAAA record
   -cname  Query CNAME record
   -ns     Query NS record
   -txt    Query TXT record
   -ptr    Query PTR record
   -mx     Query MX record
   -soa    Query SOA record

FILTERS:
   -resp               Display DNS response
   -resp-only          Display DNS response only
   -rcode, -rc string  Display DNS status code (eg. -rcode noerror,servfail,refused)

RATE-LIMIT:
   -t, -c int            Number of concurrent threads to use (default 100)
   -rl, -rate-limit int  Number of DNS request/second (disabled as default) (default -1)

OUTPUT:
   -o, -output string  File to write output (optional)
   -json               Write output in JSONL(ines) format

DEBUG:
   -silent       Show only results in the output
   -v, -verbose  Verbose output
   -raw, -debug  Display RAW DNS response
   -stats        Display stats of the running scan
   -version      Show version of dnsx

OPTIMIZATION:
   -retry int                Number of DNS retries (default 1)
   -hf, -hostsfile           Parse system host file
   -trace                    Perform DNS trace
   -trace-max-recursion int  Max recursion for dns trace (default 32767)
   -flush-interval int       Flush interval of output file (default 10)
   -resume                   Resume

CONFIGURATIONS:
   -r, -resolver string          List of resolvers (file or comma separated)
   -wt, -wildcard-threshold int  Wildcard Filter Threshold (default 5)
   -wd, -wildcard-domain string  Domain name for wildcard filtering (other flags will be ignored)
```



# Installation Instructions


dnsx requires **go1.17** to install successfully. Run the following command to get the repo -

```sh
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### Running dnsx

**dnsx** can be used to filter dead records from the list of passive subdomains obtained from various sources, for example:-

```sh
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

```sh
subfinder -silent -d hackerone.com | dnsx -silent -a -resp

a.ns.hackerone.com [162.159.0.31]
b.ns.hackerone.com [162.159.1.31]
mta-sts.hackerone.com [185.199.108.153]
events.hackerone.com [208.100.11.134]
mta-sts.managed.hackerone.com [185.199.108.153]
resources.hackerone.com [52.60.160.16]
resources.hackerone.com [52.60.165.183]
www.hackerone.com [104.16.100.52]
support.hackerone.com [104.16.53.111]
```


**dnsx** can be used to extract **A** records for the given list of subdomains, for example:-

```sh
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

```sh
subfinder -silent -d hackerone.com | dnsx -silent -cname -resp

support.hackerone.com [hackerone.zendesk.com]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [hacker0x01.github.io]
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
events.hackerone.com [whitelabel.bigmarker.com]
```

**dnsx** can be used to probe [DNS Staus code](https://github.com/projectdiscovery/dnsx/wiki/RCODE-ID-VALUE-Mapping) on given list of subdomains, for example:-

```sh
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

```sh
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



### Wildcard filtering

A special feature of **dnsx** is its ability to handle **multi-level DNS based wildcards** and do it so with very less number of DNS requests. Sometimes all the subdomains will resolve which will lead to lots of garbage in the results. The way **dnsx** handles this is it will keep track of how many subdomains point to an IP and if the count of the Subdomains increase beyond a certain small threshold, it will check for wildcard on all the levels of the hosts for that IP iteratively.

```sh
dnsx -l airbnb-subs.txt -wd airbnb.com -o output.txt
```

# 📋 Notes

- As default, **dnsx** checks for **A** record.
- As default dnsx uses Google, Cloudflare, Quad9 [resolver](https://github.com/projectdiscovery/dnsx/blob/43af78839e237ea8cbafe571df1ab0d6cbe7f445/libs/dnsx/dnsx.go#L31).
- Custom resolver list can be used using `r` flag.
- Domain name input is mandatory for wildcard elimination.
- DNS record flag can not be used when using wildcard filtering.

dnsx is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
