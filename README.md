# danfoss-shield

[![Tests](https://github.com/drg-src/danfoss-shield/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/drg-src/danfoss-shield/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/pip%20installs-none-success.svg)
![Platform](https://img.shields.io/badge/platform-Linux-informational.svg)

Finds exposed Danfoss and Dixell refrigeration controllers on a network you own, and - on the gateway that serves them - blocks new connections to them from the internet. Built for shop owners and techs who found their controllers sitting on a public IP and want that shut down now. Made by **drg-src**🐲.

> A stopgap for exposed controllers while vendor patches are pending. The firewall rules were verified to load, be recognised on re-apply, and roll back on a real Linux host (nftables / iptables), using dummy addresses. That is a load-and-remove check, not a packet-drop test against real forwarded traffic. See the [Releases](https://github.com/drg-src/danfoss-shield/releases) page for what each version includes and verifies.
>
> Prefer `SHODAN_API_KEY` over the `--api-key` flag, so the key stays out of your shell history.

## Where to run it

- `scan` / `check` / `shodan` run anywhere with Python.
- **`fix` belongs on the router or gateway** that forwards internet traffic to the controllers. Its rules sit in the FORWARD path and match the controller's **internal** address. On a machine that doesn't route that traffic, they protect nothing - the tool warns you when forwarding is off.
- **Pass the internal (LAN) address to `fix`, not the public one.** A port-forwarded public address is rewritten by DNAT before the FORWARD chain, so a rule on it never matches. `fix --all <lan>/24` finds the internal address for you; `fix` refuses a public address unless you tell it the controller really sits on a routed public address (`--routed`, see Usage).
- **Most shops don't have a Linux gateway.** If your controller is reachable from outside because of a port-forward on an ISP or consumer router, the real fix is to delete that port-forward and turn off UPnP on the router. That closes the exposure without this tool.

## What it does

* Scans a subnet or list of hosts for StoreView / AK-SM / XWEB panels, probing every listed port. Identification reads the page at `/` only: a controller that redirects `/` or shows no fingerprint there is not found
* Reports each controller's auth endpoint as **open** (HTTP 200 with a data body), **closed** (401/403/404) or **unknown** (login redirect, an HTML page or an empty body on a 200, server error, or a probe that couldn't complete). A port that refuses the connection is treated as having no service there, not as an error; an address that never answers on any port counts as unknown, is counted and printed separately, and by default makes a sweep of a range with unused addresses exit 1. `--silent-ok` stops those addresses failing the run (they are still printed); the price is that a controller behind a filter that drops or rejects probes would be missed. A scan in which no address answered at all still exits 1, with or without the flag
* Each probe has a wall-clock deadline (the larger of 10 s and 3x the timeout); a host that drips its answer slowly is cut off and counted as unknown. Tested against slow plain-HTTP servers on Windows and Linux. A slowly dripped TLS handshake ends at the normal timeout (measured on Python 3.14); a slow TLS answer after the handshake is cut off at the deadline (tested on Windows and Linux)
* Drops new inbound connections on the WAN interface to those IPs in the FORWARD path via nftables or iptables, IPv6 addresses included when you give them. Sessions already open and connections a controller opens outward are not cut. A sweep of an IPv4 range does not find IPv6 addresses the same controllers may have
* `fix` prints which fingerprint text matched for each controller it will block
* Self-lockout protection stops you blocking any of your default gateways (IPv4 and IPv6), and says so when it cannot read the routes; refuses public/port-forwarded fix targets and IPv4-mapped IPv6 targets. A controller with a routed public address (no port-forward) needs `--routed` with `--authorized`; every other check stays on. A target that is one of the gateway's own addresses is refused, because forwarding rules never see traffic for the host itself
* Every target is validated before anything is changed, only one `fix` or rollback runs at a time, and external commands that hang are stopped after 30 s and counted as failures
* Backs up your current firewall rules first (on by default); if the backup fails, nothing is changed
* Rolls back live rules across **both** backends. Only rules carrying the tool's exact tag are removed. A ruleset that cannot be listed counts as a failure. Rollback leaves the saved rule file in place; if you added it to boot persistence, remove that yourself
* Optional Shodan **lookup** of your own public range (lookup only - it does not probe or block, and stores no banners). It needs `--net` and `--authorized`; the query sent is limited to that range and the tool's six ports, and the tool itself discards any result outside the range
* Optional Suricata rules and a systemd timer for recurring scans. The timer's scan runs with `--silent-ok`, so unused addresses do not mark the job failed; an open or unknown controller, or a scan where nothing answered, still does. The rules are written but not confirmed loaded, and were not validated against a Suricata install by us: list the file under `rule-files` in `suricata.yaml` and check with `suricata -T`. They match plain HTTP only and also alert on this tool's own scans

## Requirements

Linux with root for `fix`. Needs `nft` or `iptables`. Everything else is stdlib Python 3.9+.

The examples below run the script directly. Make it executable once with `chmod +x danfoss_shield.py`, or put `python3` in front: `python3 danfoss_shield.py scan 192.168.1.0/24`.

## Usage

Scan a range you own:
```bash
./danfoss_shield.py scan 192.168.1.0/24
```

Check specific hosts:
```bash
./danfoss_shield.py check controller1.local 10.0.5.22
```

Block what you found - **run on the gateway, against internal addresses, dry-run first**:
```bash
sudo ./danfoss_shield.py fix --all 192.168.1.0/24 --wan eth0 --dry-run
sudo ./danfoss_shield.py fix --all 192.168.1.0/24 --wan eth0
```
Backup is on by default; add `--no-backup` to skip it. On a range with unused addresses, add `--silent-ok` if you want exit 0 when everything that answered was handled.

A controller that sits on a routed public address of yours, with no port-forward in front of it:
```bash
sudo ./danfoss_shield.py fix <controller-address> --wan eth0 --routed --authorized --dry-run
```

Undo everything (both backends):
```bash
sudo ./danfoss_shield.py fix --rollback
```

Internet exposure lookup (read-only; prefer the env var over the flag):
```bash
export SHODAN_API_KEY=your_key
./danfoss_shield.py shodan --net <your-public-range>/29 --authorized
```
`--net` must be your own public range in CIDR form; private and documentation-only ranges are refused. If Shodan reports more matches than one result page holds, or returns anything outside your range, the run says so and exits 1.

## Only scan what you own

`scan`, `check` and `fix` all refuse public (non-private) targets unless you pass `--authorized` to confirm you own them or have permission to test them. This is a hard default in the code, not just advice. Pointing the auth-endpoint probe at machines you don't own can be an offence in the EU and elsewhere. Keep it to your own networks.

## Legal & intended use

This is a **defensive** tool. Its purpose is to help an operator find and shut off *their own* exposed refrigeration controllers while a vendor fix is pending. After a fingerprint match it sends one GET to the controller's auth endpoint (`/xml.cgi?action=getauth` for Danfoss, `/cgi-bin/dixell.cgi` for Dixell), reads at most 2 KB of a 200 answer to tell HTML from data, and stores none of it. Then it blocks inbound access with your firewall.

- **Use it only on systems you own or are explicitly authorized in writing to test.** Unauthorized scanning or access may be a criminal offence (e.g. the UK Computer Misuse Act, the US CFAA, and equivalents in most jurisdictions). You are responsible for how you use it.
- **No data on third parties is collected or stored.** Page snippets are kept only for private/owned addresses; the optional Shodan lookup is read-only, limited to the `--net` range you give it, and stores no banners.
- **Found someone else's exposed controller?** Don't touch it. Report it to the owner, or to the vendor/national CERT through a responsible-disclosure channel. See [SECURITY.md](SECURITY.md).
- **No warranty.** Provided "AS IS" under the MIT License, without warranty or liability of any kind (see [LICENSE](LICENSE)). It is a stopgap, not a substitute for patching.

## Deployment across live stores

- **Dry-run first:** `--dry-run` to verify target IPs and your WAN interface before applying anything.
- **Backup is automatic.** If monitoring reports lost telemetry, revert with `sudo ./danfoss_shield.py fix --rollback`.
- **Verify OT access:** after blocking, test from an in-store terminal that local LAN access to the controller still works.
- **Persistence:** applied rules are saved under the data directory but are **not** reloaded after a reboot until you add them to your firewall config (e.g. `/etc/nftables.conf` or `netfilter-persistent save`). The tool prints how.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Finished; nothing left open as far as it could tell |
| `1` | Errored, interrupted, a rule failed, a usage error or refusal, a missing or hung firewall tool, or the scan could not finish (treat as "unknown", not "safe") |
| `2` | Controllers with an open auth endpoint found (only this) |
| `3` | Not root for a command that needs it, or Python older than 3.9 (only these) |

`fix` exits 1 when nothing was blocked because the scan or a name lookup did not complete, and when a named target does not resolve (the others are still blocked). `fix` never exits 2: it exits 0 or 1 depending on whether everything it found was blocked and the scan was complete. `scan` exits 2 whenever an open auth endpoint was found, even if the scan was also incomplete. `--install-suricata`, `--remove-suricata` and `--install-timer` exit 1 on failure. Exit 0 is not a statement that the controllers are safe. Useful in cron and CI.

## Files

As a normal user: config in `~/.config/danfoss-shield/config`, data/logs in `~/.local/share/danfoss-shield/`.
As root: `/etc/danfoss-shield/` and `/var/lib/danfoss-shield/`. Files are created private (0600/0700). Command-line flags override config. Numbers are checked (`--timeout` 0.1-120 s, `--workers` 1-256, `--rate-limit` 0.1-1000, or 0 for no limit); a bad number in the config file is ignored with a message and the default is used. `--wan` must be letters, digits, `_ . -` (max 15) and exist in `/sys/class/net`. If the WAN interface is unset, it is auto-detected only when the IPv4 and IPv6 default routes together name exactly one interface; otherwise (several interfaces, none, or a default route that names no interface) `fix` refuses and asks for `--wan`. Rollback never needs a WAN interface.

## Notes

Rate limiting is global across threads, so you won't melt a small network's web server while scanning. Scan results go to JSON, CSV or plain text with `-o`; CSV cells are sanitised against spreadsheet formula injection, and text that came from a device or from Shodan has its control characters replaced before it is shown or saved. Colour codes are only written to a terminal.

## Known limits

- Controllers that do not show a fingerprint at `/` are not found (needs real devices to fix).
- On a gateway with several uplinks, run `fix --wan <interface>` once per uplink.
- An IPv4 sweep does not discover a controller's IPv6 addresses.
- Existing sessions are not cut; only new inbound connections are dropped.
- The rules sit in the routed FORWARD path. A gateway that bridges the controllers' traffic instead of routing it was not tested and may not pass that traffic through these rules.
- The firewall lock that stops two runs at once exists on Linux only, which is where `fix` runs. If the lock file cannot be created, the run continues without it and says so.
- The iptables backend passes `-w 5` (wait for the xtables lock). iptables older than 1.6 does not accept that form, so on such systems every iptables command fails and `fix` exits 1; use the nftables backend there.
- `--rate-limit` accepts 0 (no limit) or 0.1 and above.
- With `--silent-ok`, an address of this host inside the scanned range counts as an answer. If everything else on the range is silent (for example a dead LAN), the run can still exit 0.
- Ctrl+C does not cut a probe that is still connecting; that probe ends within about `--timeout`.
- Firewall commands are mocked in the test suite. What each version was tested on is on the [Releases](https://github.com/drg-src/danfoss-shield/releases) page.

Blocking at the firewall is a stopgap. Patch the controllers, replace end-of-life models, or put them behind a VPN. This buys you time; it doesn't replace fixing the actual exposure.
