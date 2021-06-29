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
<a href="https://github.com/projectdiscovery/dnsx/actions/workflows/build.yaml"><img src="https://github.com/projectdiscovery/dnsx/actions/workflows/build.yaml/badge.svg?branch=master"></a>
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
 - Supports DNS Tracing
 - Handles wildcard subdomains in automated way.
 - **Stdin** and **stdout** support to work with other tools.

# Usage

```sh
dnsx -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag                | Description                        | Example               |
| ------------------- | ---------------------------------- | --------------------- |
| a                   | Query A record                     | dnsx -a               |
| aaaa                | Query AAAA record                  | dnsx -aaaa            |
| cname               | Query CNAME record                 | dnsx -cname           |
| ns                  | Query NS record                    | dnsx -ns              |
| ptr                 | Query PTR record                   | dnsx -ptr             |
| txt                 | Query TXT record                   | dnsx -txt             |
| mx                  | Query MX record                    | dnsx -mx              |
| soa                 | Query SOA record                   | dnsx -soa             |
| raw                 | Operates like dig                  | dnsx -raw             |
| rcode               | DNS Response codes                 | dnsx -rcode 0,1,2     |
| l                   | File input list of subdomains/host | dnsx -l list.txt      |
| json                | JSON output                        | dnsx -json            |
| r                   | File or comma separated resolvers  | dnsx -r 1.1.1.1       |
| rl                  | Limit of DNS request/second        | dnsx -rl 100          |
| resp                | Display response data              | dnsx -cname -resp     |
| resp-only           | Display only response data         | dnsx -cname resp-only |
| retry               | Number of DNS retries              | dnsx -retry 1         |
| silent              | Show only results in the output    | dnsx -silent          |
| stats               | Display stats of the running scan  | dnsx -stats           |
| o                   | File to write output to (optional) | dnsx -o output.txt    |
| t                   | Concurrent threads to make         | dnsx -t 100           |
| trace               | Perform dns trace                  | dnsx -trace           |
| trace-max-recursion | Max recursion for dns trace        | dnsx -t 32767         |
| verbose             | Verbose output                     | dnsx -verbose         |
| version             | Show version of dnsx               | dnsx -version         |
| wd                  | Wildcard domain name for filtering | dnsx -wd example.com  |
| wt                  | Wildcard Filter Threshold          | dnsx -wt 5            |


# Installation Instructions


dnsx requires **go1.14+** to install successfully. Run the following command to get the repo - 

```sh
GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx
```

### Running dnsx

**dnsx** can be used to filter dead records from the list of passive subdomains obtained from various sources, for example:-

```sh
▶ subfinder -silent -d hackerone.com | dnsx

      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  /
 | (_| || | | |\__ \ /  \
  \__,_||_| |_||___//_/\_\ v1.0.4

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

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
▶ subfinder -silent -d hackerone.com | dnsx -silent -a -resp

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
▶ subfinder -silent -d hackerone.com | dnsx -silent -a -resp-only

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
▶ subfinder -silent -d hackerone.com | dnsx -silent -cname -resp

support.hackerone.com [hackerone.zendesk.com]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [hacker0x01.github.io]
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
events.hackerone.com [whitelabel.bigmarker.com]
```

**dnsx** can be used to extract subdomains from given network range using `PTR` query, for example:-

```sh
mapcidr -cidr 173.0.84.0/24 -silent | dnsx -silent -resp-only -ptr

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
