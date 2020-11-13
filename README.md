<h1 align="left">
  <img src="static/dnsx-logo.png" alt="dnsx" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/dnsx)](https://goreportcard.com/report/github.com/projectdiscovery/dnsx)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/dnsx/issues)
[![GitHub Release](https://img.shields.io/github/release/projectdiscovery/dnsx)](https://github.com/projectdiscovery/dnsx/releases)
[![Follow on Twitter](https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter)](https://twitter.com/pdiscoveryio)
[![Docker Images](https://img.shields.io/docker/pulls/projectdiscovery/dnsx.svg)](https://hub.docker.com/r/projectdiscovery/dnsx)
[![Chat on Discord](https://img.shields.io/discord/695645237418131507.svg?logo=discord)](https://discord.gg/KECAGdH)

dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probers using [retryabledns](https://github.com/projectdiscovery/retryabledns) library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers.

# Resources
- [Resources](#resources)
- [Features](#features)
- [Usage](#usage)
- [Installation Instructions](#installation-instructions)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
    - [From Github](#from-github)
- [Running dnsx](#running-dnsx)
- [Notes](#-notes)
- [Note on wildcards](#note-on-wildcards)

# Features

<h1 align="left">
  <img src="static/dnsx-run.png" alt="dnsx" width="700px"></a>
  <br>
</h1>

 - Simple and Handy utility to query DNS records. 
 - Handles wildcard subdomains in automated way.
 - Optimized for **ease of use**.
 - **Stdin** and **stdout** support to work with other tools.

# Usage

```sh
dnsx -h
```
This will display help for the tool. Here are all the switches it supports.

| Flag 		| Description 						| Example |
|-----------|-----------------------------------|----------------|
| a			| Query A record					| dnsx -a	|
| aaaa 		| Query AAAA record 				| dnsx -aaaa |
| cname		| Query CNAME record 				| dnsx -cname |
| ns		| Query NS record 					| dnsx -ns |
| ptr		| Query PTR record 					| dnsx -ptr |
| txt 		| Query TXT record 					| dnsx -txt |
| mx		| DQuery MX record 					| dnsx -mx |
| soa		| Query SOA record 					| dnsx -soa |
| raw		| Operates like dig 				| dnsx -raw |
| l			| File input list of subdomains/host| dnsx -l list.txt |
| json 		| JSON output 						| dnsx -json |
| r 		| File or comma separated resolvers | dnsx -r 1.1.1.1 |
| rl 		| Limit of DNS request/second 		| dnsx -rl 100 |
| resp 		| Display response data 			| dnsx -cname -resp |
| resp-only | Display only response data 		| dnsx -cname resp-only |
| retry 	| Number of DNS retries 			| dnsx -retry 1 |
| silent 	| Show only results in the output 	| dnsx -silent |
| o 		| File to write output to (optional)| dnsx -o output.txt |
| t 		| Concurrent threads to make 		| dnsx -t 250 |
| verbose 	| Verbose output 					| dnsx -verbose |
| version 	| Show version of dnsx 				| dnsx -version |
| wd 		| Wildcard domain name for filtering| dnsx -wd example.com |
| wt 		| Wildcard Filter Threshold 		| dnsx -wt 5 |


# Installation Instructions

### From Source

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/dnsx/releases/) page. Extract them using tar, move it to your `$PATH`and you're ready to go.

```sh
Download latest binary from https://github.com/projectdiscovery/dnsx/releases

▶ tar -xvf dnsx-linux-amd64.tar
▶ mv dnsx-linux-amd64 /usr/local/bin/dnsx
▶ dnsx -h
```

### From Source

**dnsx** requires **go1.14+** to install successfully. Run the following command to get the repo - 

```sh
▶ GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx
```

### From Github

```sh
▶ git clone https://github.com/projectdiscovery/dnsx.git; cd dnsx/cmd/dnsx; go build; mv dnsx /usr/local/bin/; dnsx -version
```

### Running dnsx

To query a list of domains, you can pass the list via stdin (it also accepts full URLS, in this case the domain is extracted automatically).

```sh
▶ subfinder -silent -d hackerone.com | dnsx -resp

      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  / 
 | (_| || | | |\__ \ /  \
  \__,_||_| |_||___//_/\_\ v1.0

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

a.ns.hackerone.com [162.159.0.31]
b.ns.hackerone.com [162.159.1.31]
mta-sts.hackerone.com [185.199.108.153]
mta-sts.hackerone.com [185.199.109.153]
mta-sts.hackerone.com [185.199.110.153]
mta-sts.hackerone.com [185.199.111.153]
events.hackerone.com [208.100.11.134]
mta-sts.managed.hackerone.com [185.199.108.153]
mta-sts.managed.hackerone.com [185.199.109.153]
mta-sts.managed.hackerone.com [185.199.110.153]
mta-sts.managed.hackerone.com [185.199.111.153]
resources.hackerone.com [52.60.160.16]
resources.hackerone.com [52.60.165.183]
www.hackerone.com [104.16.100.52]
www.hackerone.com [104.16.99.52]
support.hackerone.com [104.16.51.111]
support.hackerone.com [104.16.53.111]
```

### Querying host for CNAME record

```sh
▶ subfinder -silent -d hackerone.com | dnsx -resp -cname

      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  / 
 | (_| || | | |\__ \ /  \
  \__,_||_| |_||___//_/\_\ v1.0

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

support.hackerone.com [hackerone.zendesk.com]
resources.hackerone.com [read.uberflip.com]
mta-sts.hackerone.com [hacker0x01.github.io]
mta-sts.forwarding.hackerone.com [hacker0x01.github.io]
events.hackerone.com [whitelabel.bigmarker.com]
```

# 📋 Notes

- Domain name input is mandatory for wildcard elimination.
- No other flag works when using wildcard filtering.

# Note on wildcards

A special feature of dnsX is its ability to handle multi-level DNS based wildcards and do it so with very less number of DNS requests. Sometimes all the subdomains will resolve which will lead to lots of garbage in the results. The way dnsX handles this is it will keep track of how many subdomains point to an IP and if the count of the Subdomains increase beyond a certain small threshold, it will check for wildcard on all the levels of the hosts for that IP iteratively.

dnsx is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
