# Usage with [MullvadVPN](https://mullvad.net/)
As explained in [#221](https://github.com/projectdiscovery/dnsx/issues/221), VPN operators sometimes filter high DNS/UDP traffic. To avoid packet loss you can tweak a few settings in the client app.

- 1. Go to *Settings > VPN settings* and set Wireguard as the default tunnel (the settings we need are only available with Wireguard).
- 2. Still in the same section, raise the MTU (=maximum transmission; determines the largest packet size that can be transmitted through your network) to its maximum of 1420.
- 3. Go back to *Settings > VPN settings* and add a custom DNS server (e.g Cloudfare's 1.1.1.1 & 1.0.0.1). It will disable 'DNS Protection' which is not a problem: it won't mess with our traffic system.

Happy hacking! s/o to Saber for letting me know about [#221](https://github.com/projectdiscovery/dnsx/issues/221), helped me solve this problem & understand it. If this doesn't solve the problem, open an issue and tag me (@noctisatrae).