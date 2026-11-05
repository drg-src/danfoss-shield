# danfoss-shield

[![Tests](https://github.com/drg-src/danfoss-shield/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/drg-src/danfoss-shield/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/pip%20installs-none-success.svg)
![Platform](https://img.shields.io/badge/platform-Linux-informational.svg)

Finds exposed Danfoss and Dixell refrigeration controllers on a network you own, and - on the gateway that serves them - blocks new connections to them from the internet. Built for shop owners and techs who found their controllers sitting on a public IP and want that shut down now. Made by **drg-src**🐲.

> A stopgap for exposed controllers while vendor patches are pending. Firewall rules are verified to load and roll back on current Linux (nftables / iptables). See the [Releases](https://github.com/drg-src/danfoss-shield/releases) page for what each version includes and verifies.
>
> Prefer `SHODAN_API_KEY` over the `--api-key` flag. Migrating from an earlier build and ever passed a key as a flag? Rotate it to be safe.

## Where to run it

- `scan` / `check` / `shodan` run anywhere with Python.
- **`fix` belongs on the router or gateway** that forwards internet traffic to the controllers. Its rules sit in the FORWARD path and match the controller's **internal** address. On a machine that doesn't route that traffic, they protect nothing - the tool warns you when forwarding is off.
- **Pass the internal (LAN) address to `fix`, not the public one.** A port-forwarded public address is rewritten by DNAT before the FORWARD chain, so a rule on it never matches. `fix --all <lan>/24` finds the internal address for you; `fix` refuses a public address unless you pass `--force`.
- **Most shops don't have a Linux gateway.** If your controller is reachable from outside because of a port-forward on an ISP or consumer router, the real fix is to delete that port-forward and turn off UPnP on the router. That closes the exposure without this tool.

## What it does

* Scans a subnet or list of hosts for StoreView / AK-SM / XWEB panels, probing every listed port
* Reports each controller's auth endpoint as **open** (HTTP 200), **closed** (401/403/404) or **unknown** (login redirect, server error, or a probe that couldn't complete) - it never calls a timeout "closed"
* Drops new inbound connections to those IPs in the FORWARD path via nftables or iptables, IPv6 included
* Self-lockout protection stops you blocking your default gateway; refuses public/port-forwarded fix targets
* Backs up your current firewall rules first (on by default); if the backup fails, nothing is changed
* Rolls back cleanly across **both** backends, including ineffective rules left by older builds
* Optional Shodan **lookup** for internet-facing exposure (lookup only - it does not probe or block, and stores no banners)
* Optional Suricata rules and a systemd timer for recurring scans

## Requirements

Linux with root for `fix`. Needs `nft` or `iptables`. Everything else is stdlib Python 3.9+.

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
Backup is on by default; add `--no-backup` to skip it.

Undo everything (both backends, also leftovers from older builds):
```bash
sudo ./danfoss_shield.py fix --rollback
```

Internet exposure lookup (read-only; prefer the env var over the flag):
```bash
export SHODAN_API_KEY=your_key
./danfoss_shield.py shodan
```

## Only scan what you own

`scan`, `check` and `fix` all refuse public (non-private) targets unless you pass `--authorized` to confirm you own them or have permission to test them. This is a hard default in the code, not just advice. Pointing the auth-endpoint probe at machines you don't own can be an offence in the EU and elsewhere. Keep it to your own networks.

## Legal & intended use

This is a **defensive** tool. Its purpose is to help an operator find and shut off *their own* exposed refrigeration controllers while a vendor fix is pending. It does not exploit anything - it checks whether an auth endpoint is reachable, then blocks inbound access with your firewall.

- **Use it only on systems you own or are explicitly authorized in writing to test.** Unauthorized scanning or access may be a criminal offence (e.g. the UK Computer Misuse Act, the US CFAA, and equivalents in most jurisdictions). You are responsible for how you use it.
- **No data on third parties is collected or stored.** Page snippets are kept only for private/owned addresses; the optional Shodan lookup is read-only and stores no banners.
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
| `1` | Errored, a rule failed, or the scan could not finish (treat as "unknown", not "safe") |
| `2` | Controllers with an open auth endpoint found |
| `3` | Missing deps or not root |

Useful in cron and CI.

## Files

As a normal user: config in `~/.config/danfoss-shield/config`, data/logs in `~/.local/share/danfoss-shield/`.
As root: `/etc/danfoss-shield/` and `/var/lib/danfoss-shield/`. Files are created private (0600/0700). Command-line flags override config. If the WAN interface is unset, it's auto-detected.

## Notes

Rate limiting is global across threads, so you won't melt a small network's web server while scanning. Scan results go to JSON, CSV or plain text with `-o`; CSV cells are sanitised against spreadsheet formula injection.

Blocking at the firewall is a stopgap. Patch the controllers, replace end-of-life models, or put them behind a VPN. This buys you time; it doesn't replace fixing the actual exposure.
