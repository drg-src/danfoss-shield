#!/usr/bin/env python3
"""danfoss-shield: scan a network you own for exposed Danfoss/Dixell refrigeration
controllers and block their internet access at the gateway firewall. Stopgap, not a patch. -drg"""
import argparse
import configparser
import concurrent.futures
import csv
import datetime
import http.client
import io
import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
from pathlib import Path

VERSION = "1.0.0"

DANFOSS_FINGERPRINTS = [b"StoreView", b"Danfoss", b"AK-SM", b"System Manager"]
DIXELL_FINGERPRINTS = [b"Dixell", b"XWEB"]

DANFOSS_VULN_ENDPOINT = "/xml.cgi?action=getauth"
DIXELL_VULN_ENDPOINT = "/cgi-bin/dixell.cgi"

PORTS = [80, 443, 8080, 8443, 3080, 3443]
SSL_PORTS = (443, 8443, 3443)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VULN_FOUND = 2
EXIT_MISSING_DEPS = 3

RULE_TAG = "danfoss_shield"
NFT_TABLE = ["inet", "danfoss_shield"]
NFT_CHAIN = "forward"

MAX_SCAN_HOSTS = 65536
MAX_FIX_HOSTS = 1024

AUTH_OPEN = "open"
AUTH_CLOSED = "closed"
AUTH_UNKNOWN = "unknown"

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def data_dir() -> Path:
    return Path("/var/lib/danfoss-shield") if is_root() else Path.home() / ".local" / "share" / "danfoss-shield"


def config_dir() -> Path:
    return Path("/etc/danfoss-shield") if is_root() else Path.home() / ".config" / "danfoss-shield"


def config_file() -> Path:
    return config_dir() / "config"


def log_file() -> Path:
    return data_dir() / "danfoss-shield.log"


class ColorTheme:
    def __init__(self, disabled: bool):
        self.disabled = disabled
    @property
    def GREEN(self): return '' if self.disabled else '\033[92m'
    @property
    def WARNING(self): return '' if self.disabled else '\033[93m'
    @property
    def FAIL(self): return '' if self.disabled else '\033[91m'
    @property
    def ENDC(self): return '' if self.disabled else '\033[0m'


colors = ColorTheme(False)


def redact_argv(argv) -> str:
    out = []
    skip_next = False
    for tok in argv:
        if skip_next:
            out.append("***")
            skip_next = False
            continue
        base = tok.split("=", 1)[0]
        if base.startswith("--api") and "--api-key".startswith(base):
            if "=" in tok:
                out.append(base + "=***")
            else:
                out.append(tok)
                skip_next = True
        else:
            out.append(tok)
    return " ".join(shlex.quote(t) for t in out)


def setup_logging(verbose: bool, quiet: bool, no_color: bool):
    global colors
    try:
        os.umask(0o077)
    except Exception:
        pass

    d = data_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(f"[!] Not using data dir {d} ({e}); logging to console only.\n")
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass

    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING

    logger = logging.getLogger("danfoss_shield")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    lf = log_file()
    try:
        fd = os.open(str(lf), os.O_WRONLY | os.O_CREAT | os.O_APPEND | O_NOFOLLOW, 0o600)
        os.close(fd)
        try:
            os.chmod(lf, 0o600)
        except Exception:
            pass
        fh = logging.FileHandler(lf, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except OSError as e:
        sys.stderr.write(f"[!] Not logging to {lf}: {e}\n")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    colors = ColorTheme(no_color or bool(os.environ.get("NO_COLOR")))

    try:
        uid = os.geteuid() if hasattr(os, "geteuid") else "N/A"
        logger.debug(f"[*] Audit Context: UID={uid}, host={socket.gethostname()}, args={redact_argv(sys.argv)}")
    except Exception:
        pass

    return logger


logger = logging.getLogger("danfoss_shield")


def load_config() -> dict:
    cfg = {
        "subnet": "192.168.1.0/24",
        "wan": "",
        "timeout": "3.0",
        "rate_limit": "20.0",
        "workers": "30"
    }
    cf = config_file()
    if cf.exists():
        config = configparser.ConfigParser()
        try:
            config.read(cf)
            if config.has_section("danfoss-shield"):
                for key in cfg:
                    if config.has_option("danfoss-shield", key):
                        cfg[key] = config.get("danfoss-shield", key)
        except Exception as e:
            logger.warning(f"Failed to parse config file {cf}: {e}")
    return cfg


def check_dependencies():
    if sys.version_info < (3, 9):
        print("[-] Error: Python 3.9 or higher is required.", file=sys.stderr)
        sys.exit(EXIT_MISSING_DEPS)


def detect_firewall_backend(preference: str) -> str:
    if preference != "auto":
        return preference
    for tool, name in (("nft", "nftables"), ("iptables", "iptables")):
        try:
            if subprocess.run([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return name
        except FileNotFoundError:
            pass
    return "none"


def auto_detect_wan_interface() -> str:
    try:
        res = subprocess.run(["ip", "route", "show", "default"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        m = re.search(r"dev\s+(\S+)", res.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        interfaces = [i for i in os.listdir("/sys/class/net") if i != "lo"]
        if interfaces:
            return interfaces[0]
    except Exception:
        pass
    return "eth0"


def validate_wan_interface(wan: str):
    if not wan or not (Path("/sys/class/net") / wan).exists():
        raise ValueError(f"Safety Error: WAN interface '{wan}' does not exist in /sys/class/net/. Verify interface name.")


def get_default_gateway_ip() -> "str | None":
    try:
        res = subprocess.run(["ip", "route", "show", "default"], stdout=subprocess.PIPE, text=True, check=True)
        m = re.search(r"via\s+(\S+)", res.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def host_forwards(v6: bool) -> "bool | None":
    path = "/proc/sys/net/ipv6/conf/all/forwarding" if v6 else "/proc/sys/net/ipv4/ip_forward"
    try:
        return Path(path).read_text().strip() == "1"
    except Exception:
        return None


def is_local_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def resolve_target(target: str, max_hosts: int) -> "tuple[list[str], bool]":
    target = target.strip()
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.num_addresses > max_hosts:
            raise ValueError(
                f"Target {target} has {net.num_addresses} addresses, over the cap of {max_hosts}. "
                f"Narrow the range (a /16 is already 65k hosts)."
            )
        hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        return hosts, True

    try:
        ips = []
        for info in socket.getaddrinfo(target, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if ips:
            return ips, True
        return [], False
    except socket.gaierror as e:
        logger.error(f"Failed to resolve hostname '{target}': {e}")
        return [], False


def require_authorized(ips: "list[str]", authorized: bool):
    public = [ip for ip in ips if not is_local_address(ip)]
    if public and not authorized:
        sample = ", ".join(public[:5]) + (" ..." if len(public) > 5 else "")
        raise ValueError(
            f"{len(public)} target(s) are public addresses ({sample}). Probing systems you do not own or "
            f"administer can be a crime in the EU and elsewhere. If you own or are authorized to test them, "
            f"re-run with --authorized."
        )


rate_limit_lock = threading.Lock()
last_request_time = 0.0


def enforce_rate_limit(rate_limit: float):
    global last_request_time
    if rate_limit <= 0:
        return
    with rate_limit_lock:
        now = time.time()
        elapsed = now - last_request_time
        interval = 1.0 / rate_limit
        if elapsed < interval:
            time.sleep(interval - elapsed)
        last_request_time = time.time()


def _connect(host: str, port: int, timeout: float):
    if port in SSL_PORTS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def http_probe(host: str, port: int, timeout: float, rate_limit: float) -> "tuple[bytes | None, str, bool]":
    enforce_rate_limit(rate_limit)
    try:
        conn = _connect(host, port, timeout)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read(65536)
        conn.close()
        if any(fp in body for fp in DANFOSS_FINGERPRINTS):
            return body, "Danfoss StoreView", False
        if any(fp in body for fp in DIXELL_FINGERPRINTS):
            return body, "Dixell XWEB Pro", False
        return body, "", False
    except Exception:
        return None, "", True


def check_auth_endpoint(host: str, port: int, ctype: str, timeout: float, rate_limit: float) -> str:
    enforce_rate_limit(rate_limit)
    endpoint = DANFOSS_VULN_ENDPOINT if "Danfoss" in ctype else DIXELL_VULN_ENDPOINT
    try:
        conn = _connect(host, port, timeout)
        conn.request("GET", endpoint)
        resp = conn.getresponse()
        code = resp.status
        body = resp.read(2048) if code == 200 else b""
        conn.close()
        if code == 200:
            head = body.lstrip().lower()
            if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
                return AUTH_UNKNOWN
            return AUTH_OPEN
        if code in (401, 403, 404):
            return AUTH_CLOSED
        return AUTH_UNKNOWN
    except Exception:
        return AUTH_UNKNOWN


def scan_host(ip: str, timeout: float, rate_limit: float) -> "dict | None":
    found = None
    errored_ports = []
    for port in PORTS:
        body, ctype, errored = http_probe(ip, port, timeout, rate_limit)
        if errored:
            errored_ports.append(port)
            continue
        if not ctype:
            continue
        auth = check_auth_endpoint(ip, port, ctype, timeout, rate_limit)
        rank = {AUTH_OPEN: 3, AUTH_UNKNOWN: 2, AUTH_CLOSED: 1}
        if found is None or rank[auth] > rank[found["auth"]]:
            found = {
                "ip": ip, "port": port, "controller": ctype, "auth": auth,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "body_snippet": (body[:150].decode('latin1', errors='ignore') if (body and is_local_address(ip)) else "")
            }
    if found is not None:
        if errored_ports and found["auth"] != AUTH_OPEN:
            found["auth"] = AUTH_UNKNOWN
            found["partial_probe"] = errored_ports
        return found
    if errored_ports:
        return {"ip": ip, "port": None, "controller": "", "auth": AUTH_UNKNOWN,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "body_snippet": "", "probe_error": True}
    return None


def scan_targets(targets, workers, timeout, rate_limit, max_hosts, authorized=False) -> "tuple[list[dict], dict]":
    all_ips = []
    meta = {"unresolved": [], "total": 0, "probe_errors": 0}
    for t in targets:
        ips, ok = resolve_target(t, max_hosts)
        if not ok:
            meta["unresolved"].append(t)
        all_ips.extend(ips)
    all_ips = list(dict.fromkeys(all_ips))
    require_authorized(all_ips, authorized)

    meta["total"] = len(all_ips)
    logger.info(f"[*] Starting scan across {len(all_ips)} resolved IP address(es)...")

    results = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(scan_host, ip, timeout, rate_limit): ip for ip in all_ips}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if done % 10 == 0 or done == len(all_ips):
                logger.info(f"    Scanned {done}/{len(all_ips)} hosts...")
            r = fut.result()
            if not r:
                continue
            if r.get("probe_error") and not r["controller"]:
                meta["probe_errors"] += 1
                continue
            results.append(r)
            if r["auth"] == AUTH_OPEN:
                tag = f"{colors.FAIL}AUTH ENDPOINT OPEN (likely vulnerable){colors.ENDC}"
            elif r["auth"] == AUTH_UNKNOWN:
                tag = f"{colors.WARNING}EXPOSED (auth state unknown){colors.ENDC}"
            else:
                tag = f"{colors.WARNING}EXPOSED (auth endpoint closed){colors.ENDC}"
            logger.info(f"  [FOUND] {r['ip']}:{r['port']} ({r['controller']}) -> {tag}")
    return results, meta


def _safe_write_text(path: Path, text: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def backup_existing_rules(backend: str):
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = d / f"backup-{backend}-{date_str}.rules"
    try:
        if backend == "nftables":
            res = subprocess.run(["nft", "list", "ruleset"], stdout=subprocess.PIPE, text=True, check=True)
            _safe_write_text(backup_file, res.stdout)
        elif backend == "iptables":
            out = []
            for tool in ("iptables-save", "ip6tables-save"):
                try:
                    out.append(subprocess.run([tool], stdout=subprocess.PIPE, text=True, check=True).stdout)
                except FileNotFoundError:
                    pass
            if not out:
                raise RuntimeError("iptables-save not found")
            _safe_write_text(backup_file, "\n".join(out))
        logger.info(f"[*] Firewall rules backed up to {backup_file}")
    except Exception as e:
        raise RuntimeError(f"Backup failed ({e}); nothing was changed. Fix the cause or re-run with --no-backup.")


def save_applied_rules(backend: str):
    try:
        if backend == "nftables":
            res = subprocess.run(["nft", "list", "table"] + NFT_TABLE, stdout=subprocess.PIPE, text=True, check=True)
            out = data_dir() / "danfoss_shield.nft"
            _safe_write_text(out, res.stdout)
            hint = f"add 'include \"{out}\"' to /etc/nftables.conf and enable nftables.service"
        else:
            dump = []
            for tool in ("iptables-save", "ip6tables-save"):
                try:
                    dump.append(subprocess.run([tool], stdout=subprocess.PIPE, text=True, check=True).stdout)
                except FileNotFoundError:
                    pass
            out = data_dir() / "danfoss_shield.iptables"
            _safe_write_text(out, "\n".join(dump))
            hint = "use your distro's persistence (e.g. netfilter-persistent save)"
        logger.warning(f"[!] Rules are live but NOT persistent across reboot. Saved to {out}; to persist, {hint}.")
    except Exception as e:
        logger.warning(f"[!] Rules are live but NOT persistent across reboot, and saving them failed: {e}")


def nft_rule_args(ip: str, wan: str) -> "list[str]":
    fam = "ip6" if ":" in ip else "ip"
    return ["iifname", wan, fam, "daddr", ip, "ct", "state", "new", "counter", "drop", "comment", RULE_TAG]


def ipt_rule_args(ip: str, wan: str) -> "list[str]":
    return ["-i", wan, "-d", ip, "-m", "conntrack", "--ctstate", "NEW",
            "-m", "comment", "--comment", RULE_TAG, "-j", "DROP"]


def nft_table_exists() -> bool:
    return subprocess.run(["nft", "list", "table"] + NFT_TABLE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def check_rule_exists(backend: str, ip: str, wan: str) -> bool:
    try:
        if backend == "iptables":
            tool = "ip6tables" if ":" in ip else "iptables"
            return subprocess.run([tool, "-C", "FORWARD"] + ipt_rule_args(ip, wan),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if backend == "nftables":
            res = subprocess.run(["nft", "list", "chain"] + NFT_TABLE + [NFT_CHAIN],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if res.returncode != 0:
                return False
            for line in res.stdout.splitlines():
                tokens = line.split()
                if RULE_TAG not in line or f'"{wan}"' not in tokens:
                    continue
                if "daddr" in tokens and tokens.index("daddr") + 1 < len(tokens) and tokens[tokens.index("daddr") + 1] == ip:
                    return True
    except Exception:
        pass
    return False


def _run(cmd: "list[str]", dry_run: bool, quiet_fail: bool = False) -> bool:
    if dry_run:
        logger.info(f"[DRY-RUN] {' '.join(cmd)}")
        return True
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0 and not quiet_fail:
        logger.error(f"[-] Command failed: {' '.join(cmd)}: {res.stderr.strip()}")
    return res.returncode == 0


def remove_iptables_tagged(chains, dry_run) -> "tuple[int, int]":
    removed = failed = 0
    for tool in ("iptables", "ip6tables"):
        for chain in chains:
            try:
                res = subprocess.run([tool, "-S", chain], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
            except Exception as e:
                logger.debug(f"{tool} -S {chain} failed: {e}")
                continue
            for line in res.stdout.splitlines():
                if RULE_TAG not in line or not line.startswith("-A "):
                    continue
                args = shlex.split(line)
                args[0] = "-D"
                if _run([tool] + args, dry_run):
                    removed += 1
                else:
                    failed += 1
    return removed, failed


def remove_legacy_input_rules(backend: str, dry_run: bool):
    if backend == "nftables":
        exists = subprocess.run(["nft", "list", "chain"] + NFT_TABLE + ["input"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if exists:
            logger.info("[*] Removing ineffective legacy rules (nftables 'input' chain from older builds).")
            _run(["nft", "flush", "chain"] + NFT_TABLE + ["input"], dry_run)
            _run(["nft", "delete", "chain"] + NFT_TABLE + ["input"], dry_run)
    elif backend == "iptables":
        n, _ = remove_iptables_tagged(["INPUT"], dry_run)
        if n:
            logger.info(f"[*] Removed {n} ineffective legacy INPUT rule(s) from older builds.")


def rollback_all(dry_run: bool) -> dict:
    summary = {"removed": 0, "failed": 0}
    if not dry_run and not is_root():
        raise PermissionError("Rollback requires root privileges (run with sudo).")
    have_nft = detect_firewall_backend("auto") == "nftables" or _tool_present("nft")
    have_ipt = _tool_present("iptables")
    summary["backends"] = int(have_nft) + int(have_ipt)

    if have_nft:
        if dry_run:
            logger.info("[DRY-RUN] nft delete table " + " ".join(NFT_TABLE) + " (if present)")
        elif nft_table_exists():
            if _run(["nft", "delete", "table"] + NFT_TABLE, dry_run):
                logger.info("[+] Removed nftables table inet danfoss_shield")
                summary["removed"] += 1
            else:
                summary["failed"] += 1
        else:
            logger.info("[*] No nftables table inet danfoss_shield present.")
    if have_ipt:
        r, f = remove_iptables_tagged(["FORWARD", "INPUT"], dry_run)
        summary["removed"] += r
        summary["failed"] += f
    if not have_nft and not have_ipt:
        logger.warning("[!] Neither nft nor iptables found; nothing could be rolled back.")
    return summary


def _tool_present(tool: str) -> bool:
    try:
        return subprocess.run([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        return False


def apply_firewall_rules(ips, wan, backend, dry_run, force, backup) -> dict:
    summary = {"applied": 0, "existing": 0, "skipped": 0}
    if backend not in ("nftables", "iptables"):
        raise ValueError("No supported firewall backend found (need nft or iptables).")
    if not dry_run and not is_root():
        raise PermissionError("Firewall modification requires root privileges (run with sudo).")

    validate_wan_interface(wan)

    non_local = [ip for ip in ips if not is_local_address(ip)]
    if non_local and not force:
        sample = ", ".join(non_local[:5]) + (" ..." if len(non_local) > 5 else "")
        raise ValueError(
            f"fix targets must be the controller's INTERNAL address. These look public: {sample}. "
            f"On a gateway, DNAT rewrites a port-forwarded address before FORWARD, so the rule would "
            f"never match. Pass the LAN address (or use `fix --all <lan>/24`). Use --force to override."
        )

    gw = get_default_gateway_ip()
    if gw and gw in ips:
        if not force:
            raise ValueError(f"Safety Abort: Target list includes default gateway IP ({gw}). Use --force to override.")
        logger.warning(f"[!] WARNING: Overriding gateway protection for IP {gw} due to --force flag.")

    for v6 in (False, True):
        if any((":" in ip) == v6 for ip in ips) and host_forwards(v6) is False:
            fam = "IPv6" if v6 else "IPv4"
            logger.warning(f"[!] WARNING: {fam} forwarding is off on this host. These rules only protect "
                           f"controllers when this host is the router/gateway their traffic passes through.")

    if not dry_run and backup:
        backup_existing_rules(backend)

    remove_legacy_input_rules(backend, dry_run)

    if backend == "nftables":
        _run(["nft", "add", "table"] + NFT_TABLE, dry_run)
        _run(["nft", "add", "chain"] + NFT_TABLE +
             [NFT_CHAIN, "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}"], dry_run)

    for ip in ips:
        ip = str(ipaddress.ip_address(ip))
        if not dry_run and check_rule_exists(backend, ip, wan) and not force:
            summary["existing"] += 1
            continue
        if backend == "nftables":
            cmd = ["nft", "add", "rule"] + NFT_TABLE + [NFT_CHAIN] + nft_rule_args(ip, wan)
        else:
            tool = "ip6tables" if ":" in ip else "iptables"
            cmd = [tool, "-I", "FORWARD"] + ipt_rule_args(ip, wan)
        if _run(cmd, dry_run):
            summary["applied"] += 1
        else:
            summary["skipped"] += 1

    if not dry_run and summary["applied"]:
        save_applied_rules(backend)
    return summary


def query_shodan(api_key: str, query: str) -> "tuple[list[dict] | None, bool]":
    url = f"https://api.shodan.io/shodan/host/search?key={urllib.parse.quote(api_key)}&query={urllib.parse.quote(query)}"
    logger.info("[*] Querying Shodan API...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"danfoss-shield/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not isinstance(data, dict) or data.get("error") or "matches" not in data:
            logger.error("[-] Shodan API did not return a valid result set (treating as failure).")
            return None, False
        results = []
        for m in data.get("matches", []):
            banner = m.get("data", "")
            banner_bytes = banner.encode('latin1', errors='ignore')
            ctype = "Unknown"
            if any(fp in banner_bytes for fp in DANFOSS_FINGERPRINTS):
                ctype = "Danfoss StoreView"
            elif any(fp in banner_bytes for fp in DIXELL_FINGERPRINTS):
                ctype = "Dixell XWEB Pro"
            results.append({"ip": m.get("ip_str"), "port": m.get("port"), "controller": ctype,
                            "org": m.get("org", "Unknown")})
        return results, True
    except Exception as e:
        logger.error(f"[-] Shodan API query failed: {type(e).__name__}")
        return None, False


def _exec_start(subnet: str, scans_dir: Path) -> "list[str]":
    out = scans_dir / "scan-latest.json"
    return [sys.executable, os.path.abspath(sys.argv[0]), "--quiet", "scan", subnet, "--output", str(out)]


def install_systemd_timer(scan_subnet: str):
    try:
        ipaddress.ip_network(scan_subnet, strict=False)
    except ValueError:
        logger.error(f"[-] Config subnet '{scan_subnet}' is not a valid network; refusing to write the unit.")
        sys.exit(EXIT_ERROR)

    target_dir = Path.home() / ".config" / "systemd" / "user"
    target_dir.mkdir(parents=True, exist_ok=True)
    scans_dir = data_dir() / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    argv = _exec_start(scan_subnet, scans_dir)

    ok, err = _parse_check(argv[2:])
    if not ok:
        logger.error(f"[-] Generated scan command does not parse ({err}); not writing the timer.")
        sys.exit(EXIT_ERROR)

    exec_start = " ".join(shlex.quote(a) for a in argv)
    service_content = ("[Unit]\n"
                       "Description=danfoss-shield periodic refrigeration controller scan\n"
                       "After=network.target\n\n"
                       "[Service]\n"
                       "Type=oneshot\n"
                       f"ExecStart={exec_start}\n")
    timer_content = ("[Unit]\n"
                     "Description=Run danfoss-shield every 6 hours\n\n"
                     "[Timer]\n"
                     "Persistent=true\n"
                     "OnBootSec=5min\n"
                     "OnUnitActiveSec=6h\n\n"
                     "[Install]\n"
                     "WantedBy=timers.target\n")
    _safe_write_text(target_dir / "danfoss-shield.service", service_content)
    _safe_write_text(target_dir / "danfoss-shield.timer", timer_content)
    logger.info(f"[+] Installed systemd units to {target_dir}")
    logger.info("    systemctl --user daemon-reload && systemctl --user enable --now danfoss-shield.timer")


def install_suricata_rules():
    rule_dir = Path("/etc/suricata/rules")
    if not is_root():
        logger.warning("[!] Not running as root; writing Suricata rules to the data directory instead of /etc/suricata/rules.")
        rule_dir = data_dir() / "rules"
    rule_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rule_dir / "danfoss-shield-fromagegate.rules"
    rule_content = ('# Suricata ruleset for detecting fromagegate refrigeration exploits\n'
                    'alert tcp any any -> any [80,443,8080,8443,3080,3443] (msg:"ET EXPLOIT Danfoss StoreView Auth Bypass (CVE-2025-41450) Attempt"; content:"/xml.cgi?action=getauth"; fast_pattern; classtype:attempt-exploit; sid:9900001; rev:1;)\n'
                    'alert tcp any any -> any [80,443,8080,8443,3080,3443] (msg:"ET EXPLOIT Dixell XWEB Pro Unauthorized Command Attempt"; content:"/cgi-bin/dixell.cgi"; fast_pattern; classtype:attempt-exploit; sid:9900002; rev:1;)\n')
    try:
        _safe_write_text(rule_file, rule_content)
        logger.info(f"[+] Suricata detection rules written to {rule_file}")
        if is_root():
            subprocess.run(["systemctl", "reload", "suricata"], check=False)
    except Exception as e:
        logger.error(f"[-] Failed to install Suricata rules: {e}")


def remove_suricata_rules():
    for path in [Path("/etc/suricata/rules/danfoss-shield-fromagegate.rules"),
                 data_dir() / "rules" / "danfoss-shield-fromagegate.rules"]:
        if path.exists():
            path.unlink()
            logger.info(f"[+] Removed Suricata rule file: {path}")


def csv_safe(value):
    if not isinstance(value, str):
        return value
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def export_results(results, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        _safe_write_text(path, json.dumps(results, indent=2))
    elif path.suffix == ".csv":
        keys = list(results[0].keys()) if results else ["ip", "port", "controller", "auth", "timestamp"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow({k: csv_safe(r.get(k)) for k in keys})
        _safe_write_text(path, buf.getvalue())
    else:
        lines = [f"{csv_safe(r['ip'])}:{r.get('port')} | {csv_safe(r.get('controller', 'Unknown'))} | auth: {csv_safe(r.get('auth', '?'))}" for r in results]
        _safe_write_text(path, "\n".join(lines))
    logger.info(f"[*] Results exported to {output_path}")


def build_parser(cfg) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"danfoss-shield {VERSION}: refrigeration controller exposure scanner and gateway firewall helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=("Examples:\n"
                "  python3 danfoss_shield.py scan 192.168.1.0/24\n"
                "  sudo python3 danfoss_shield.py fix --all 192.168.1.0/24 --wan eth0 --dry-run\n"
                "Run `fix` on the gateway, against the controller's INTERNAL address.\n"
                "Only scan networks you own or are authorized to test."))
    parser.add_argument("--version", action="version", version=f"danfoss-shield {VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (warnings/errors only)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--backend", choices=["auto", "nftables", "iptables"], default="auto", help="Firewall backend")
    parser.add_argument("--install-timer", action="store_true", help="Install systemd periodic scan timer")
    parser.add_argument("--install-suricata", action="store_true", help="Install Suricata detection rules")
    parser.add_argument("--remove-suricata", action="store_true", help="Remove Suricata detection rules")

    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Scan your own network for exposed controllers", allow_abbrev=False)
    p_scan.add_argument("targets", nargs="*", default=[cfg["subnet"]])
    p_scan.add_argument("-w", "--workers", type=int, default=int(cfg["workers"]))
    p_scan.add_argument("--timeout", type=float, default=float(cfg["timeout"]))
    p_scan.add_argument("--rate-limit", type=float, default=float(cfg["rate_limit"]))
    p_scan.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")
    p_scan.add_argument("-o", "--output", help="Output file (.json, .csv, .txt)")

    p_check = sub.add_parser("check", help="Check specific IPs or hostnames you own", allow_abbrev=False)
    p_check.add_argument("targets", nargs="+")
    p_check.add_argument("--timeout", type=float, default=float(cfg["timeout"]))
    p_check.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")
    p_check.add_argument("-o", "--output", help="Output file")

    p_fix = sub.add_parser("fix", help="Block new WAN connections to controllers (run on the gateway)", allow_abbrev=False)
    p_fix.add_argument("targets", nargs="*")
    p_fix.add_argument("--all", action="store_true", help="Scan the targets and block every controller found")
    p_fix.add_argument("--wan", default=None, help="WAN interface (default: config value, else auto-detected)")
    p_fix.add_argument("--dry-run", action="store_true", help="Print rules without applying")
    p_fix.add_argument("--force", action="store_true", help="Re-add existing rules / bypass safety locks")
    p_fix.add_argument("--rollback", action="store_true", help="Remove all danfoss-shield rules (both backends, incl. v1.0.1)")
    p_fix.add_argument("--backup", action="store_true", default=True, help="Backup existing rules before applying (default)")
    p_fix.add_argument("--no-backup", action="store_false", dest="backup", help="Skip the rule backup")
    p_fix.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")

    p_shod = sub.add_parser("shodan", help="Look up internet exposure via the Shodan API (no probing, no blocking)", allow_abbrev=False)
    p_shod.add_argument("--api-key", default=os.environ.get("SHODAN_API_KEY"),
                        help="Shodan API key (prefer the SHODAN_API_KEY env var; a flag also lands in shell history)")
    p_shod.add_argument("--query", default='port:80,443,3080,3443 "StoreView" OR "Danfoss" OR "Dixell"')
    p_shod.add_argument("-o", "--output", help="Output file")
    return p_scan, p_check, p_fix, p_shod, parser


_PARSE_CHECK_PARSER = None


def _parse_check(args) -> "tuple[bool, str]":
    global _PARSE_CHECK_PARSER
    if _PARSE_CHECK_PARSER is None:
        _PARSE_CHECK_PARSER = build_parser(load_config())[-1]
    try:
        import io, contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            _PARSE_CHECK_PARSER.parse_args(args)
        return True, ""
    except SystemExit:
        return False, err.getvalue().strip()


def main():
    check_dependencies()
    cfg = load_config()
    _, _, _, _, parser = build_parser(cfg)
    args = parser.parse_args()

    setup_logging(args.verbose, args.quiet, args.no_color)

    if args.install_timer:
        install_systemd_timer(cfg["subnet"])
        sys.exit(EXIT_OK)
    if args.install_suricata:
        install_suricata_rules()
        sys.exit(EXIT_OK)
    if args.remove_suricata:
        remove_suricata_rules()
        sys.exit(EXIT_OK)
    if not args.cmd:
        parser.print_help()
        sys.exit(EXIT_OK)

    logger.info("[i] danfoss-shield is a defensive tool - use only on networks/hosts you own or are "
                "authorized to test. MIT, no warranty. See LICENSE & README.")

    try:
        if args.cmd in ("scan", "check"):
            if args.cmd == "scan":
                results, meta = scan_targets(args.targets, args.workers, args.timeout, args.rate_limit,
                                             MAX_SCAN_HOSTS, args.authorized)
            else:
                results, meta = scan_targets(args.targets, 10, args.timeout, 10.0, MAX_SCAN_HOSTS, args.authorized)

            open_count = sum(1 for r in results if r["auth"] == AUTH_OPEN)
            unknown_count = sum(1 for r in results if r["auth"] == AUTH_UNKNOWN)
            closed_count = sum(1 for r in results if r["auth"] == AUTH_CLOSED)

            print("\n=== SCAN SUMMARY ===")
            print(f"Resolved IPs:       {meta['total']}")
            print(f"Controllers found:  {len(results)}")
            print(f"  auth open:        {open_count}")
            print(f"  auth unknown:     {unknown_count}")
            print(f"  auth closed:      {closed_count}")
            if meta["unresolved"]:
                print(f"Unresolved targets: {len(meta['unresolved'])} ({', '.join(meta['unresolved'][:5])})")
            if meta["probe_errors"]:
                print(f"Hosts with probe errors (state unknown): {meta['probe_errors']}")

            if args.output:
                export_results(results, args.output)

            if open_count > 0:
                sys.exit(EXIT_VULN_FOUND)
            if meta["unresolved"] or meta["probe_errors"] or unknown_count:
                sys.exit(EXIT_ERROR)
            sys.exit(EXIT_OK)

        elif args.cmd == "fix":
            backend = detect_firewall_backend(args.backend)
            wan = args.wan or cfg.get("wan") or auto_detect_wan_interface()

            if args.rollback:
                summary = rollback_all(args.dry_run)
                print(f"\nRolled back: removed {summary['removed']}, failed {summary['failed']}")
                sys.exit(EXIT_ERROR if (summary["failed"] or summary.get("backends", 0) == 0) else EXIT_OK)

            ips_to_block = []
            fix_partial = False
            if args.all:
                scan_list = args.targets if args.targets else [cfg["subnet"]]
                scan_res, meta = scan_targets(scan_list, 30, 3.0, 20.0, MAX_FIX_HOSTS, args.authorized)
                ips_to_block.extend(r["ip"] for r in scan_res if r["controller"])
                if meta["probe_errors"] or meta["unresolved"]:
                    fix_partial = True
                    logger.warning(f"[!] Scan was partial (probe errors: {meta['probe_errors']}, "
                                   f"unresolved: {len(meta['unresolved'])}); some controllers may be left unblocked.")
            elif args.targets:
                for t in args.targets:
                    ips, _ok = resolve_target(t, MAX_FIX_HOSTS)
                    ips_to_block.extend(ips)
                require_authorized(ips_to_block, args.authorized)
            else:
                logger.error("[-] Error: specify targets, use --all with targets, or use --rollback")
                sys.exit(EXIT_ERROR)

            ips_to_block = list(dict.fromkeys(ips_to_block))
            if not ips_to_block:
                logger.info("[*] No target IPs identified for blocking.")
                sys.exit(EXIT_OK)

            logger.info(f"[*] Backend: {backend} | WAN Interface: {wan}")
            summary = apply_firewall_rules(ips_to_block, wan, backend, args.dry_run, args.force, args.backup)
            print("\n=== FIX SUMMARY ===")
            print(f"Target IPs:        {len(ips_to_block)}")
            print(f"Newly applied:     {summary['applied']}")
            print(f"Already existing:  {summary['existing']}")
            print(f"Skipped (failed):  {summary['skipped']}")
            sys.exit(EXIT_ERROR if (summary["skipped"] or fix_partial) else EXIT_OK)

        elif args.cmd == "shodan":
            if not args.api_key:
                logger.error("[-] Error: Shodan API key required (--api-key or SHODAN_API_KEY env var).")
                sys.exit(EXIT_ERROR)
            results, ok = query_shodan(args.api_key, args.query)
            if not ok:
                sys.exit(EXIT_ERROR)
            logger.info(f"[+] Found {len(results)} matching hosts on Shodan (lookup only; nothing was probed).")
            for r in results:
                print(f"  {r['ip']}:{r['port']} ({r['controller']}) [{r['org']}]")
            if args.output:
                export_results(results, args.output)
            sys.exit(EXIT_OK)

    except PermissionError as e:
        logger.error(f"[-] Error: {e}")
        sys.exit(EXIT_MISSING_DEPS)
    except (ValueError, RuntimeError) as e:
        logger.error(f"[-] Error: {e}")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
