#!/usr/bin/env python3
"""danfoss-shield: scan a network you own for exposed Danfoss/Dixell refrigeration
controllers and block their internet access at the gateway firewall. Stopgap, not a patch."""
import argparse
import configparser
import concurrent.futures
import contextlib
import csv
import datetime
import errno
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

VERSION = "1.0.1"

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

PROBE_DEADLINE_MIN = 10.0
WAN_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
SURICATA_RULE_FILE = "danfoss-shield-fromagegate.rules"

CMD_TIMEOUT = 30.0
IPT_WAIT = ["-w", "5"]
SHODAN_MAX_BYTES = 5 * 1024 * 1024
TEXT_LIMIT = 200

TIMEOUT_RANGE = (0.1, 120.0)
WORKERS_RANGE = (1, 256)
RATE_RANGE = (0.0, 1000.0)

NO_ANSWER_ERRNOS = {getattr(errno, name) for name in ("EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ETIMEDOUT")
                    if hasattr(errno, name)}
NO_ANSWER_WINERRORS = {10051, 10060, 10065}

AUTH_OPEN = "open"
AUTH_CLOSED = "closed"
AUTH_UNKNOWN = "unknown"

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class NeedsRoot(PermissionError):
    pass


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _proc(cmd, **kwargs):
    try:
        return subprocess.run(cmd, timeout=CMD_TIMEOUT, **kwargs)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"{cmd[0]} did not finish within {CMD_TIMEOUT:.0f}s") from None


def clean_text(value, limit: int = TEXT_LIMIT):
    if not isinstance(value, str):
        return value
    return "".join(ch if ch.isprintable() else "?" for ch in value)[:limit]


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
    for old in list(logger.handlers):
        logger.removeHandler(old)
        try:
            old.close()
        except Exception:
            pass

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

    try:
        is_tty = sys.stdout.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    colors = ColorTheme(no_color or bool(os.environ.get("NO_COLOR")) or not is_tty)

    try:
        uid = os.geteuid() if hasattr(os, "geteuid") else "N/A"
        logger.debug(f"[*] Audit Context: UID={uid}, host={socket.gethostname()}, args={redact_argv(sys.argv)}")
    except Exception:
        pass

    return logger


logger = logging.getLogger("danfoss_shield")


CONFIG_DEFAULTS = {
    "subnet": "192.168.1.0/24",
    "wan": "",
    "timeout": "3.0",
    "rate_limit": "20.0",
    "workers": "30"
}
CONFIG_NUMERIC = {"timeout": (float, TIMEOUT_RANGE), "rate_limit": (float, RATE_RANGE), "workers": (int, WORKERS_RANGE)}


RATE_MIN_NONZERO = 0.1


def _in_range(kind, text: str, bounds) -> bool:
    try:
        value = kind(text)
    except (TypeError, ValueError):
        return False
    if not (value == value and bounds[0] <= value <= bounds[1]):
        return False
    return not (bounds is RATE_RANGE and 0 < value < RATE_MIN_NONZERO)


def load_config() -> dict:
    cfg = dict(CONFIG_DEFAULTS)
    try:
        cf = config_file()
        if not cf.exists():
            return cfg
        config = configparser.ConfigParser()
        config.read(cf)
        if config.has_section("danfoss-shield"):
            for key in cfg:
                if config.has_option("danfoss-shield", key):
                    cfg[key] = config.get("danfoss-shield", key).strip()
    except Exception as e:
        sys.stderr.write(f"[!] Config file ignored ({type(e).__name__}: {e}); using defaults.\n")
        return dict(CONFIG_DEFAULTS)
    for key, (kind, bounds) in CONFIG_NUMERIC.items():
        if not _in_range(kind, cfg[key], bounds):
            sys.stderr.write(f"[!] Config value {key}={cfg[key]!r} is not {_range_text(bounds)}; "
                             f"using the default {CONFIG_DEFAULTS[key]}.\n")
            cfg[key] = CONFIG_DEFAULTS[key]
    return cfg


def _range_text(bounds) -> str:
    if bounds is RATE_RANGE:
        return f"a number between {RATE_MIN_NONZERO} and {bounds[1]}, or 0 for no limit"
    return f"a number between {bounds[0]} and {bounds[1]}"


def bounded_number(kind, bounds, label: str):
    def parse(text: str):
        if not _in_range(kind, text, bounds):
            raise argparse.ArgumentTypeError(f"{label} must be {_range_text(bounds)}, got {text!r}")
        return kind(text)
    return parse


def check_dependencies():
    if sys.version_info < (3, 9):
        print("[-] Error: Python 3.9 or higher is required.", file=sys.stderr)
        sys.exit(EXIT_MISSING_DEPS)


def detect_firewall_backend(preference: str) -> str:
    if preference != "auto":
        return preference
    for tool, name in (("nft", "nftables"), ("iptables", "iptables")):
        try:
            if _proc([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return name
        except FileNotFoundError:
            pass
    return "none"


def auto_detect_wan_interface() -> str:
    devices = []
    for cmd in (["ip", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]):
        try:
            res = _proc(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as e:
            raise ValueError(
                f"Could not read the default routes ({' '.join(cmd)}: {type(e).__name__}), so the WAN interface "
                f"cannot be detected safely. Pass --wan <interface>."
            )
        route_lines = res.stdout.splitlines()
        for i, line in enumerate(route_lines):
            if line.split()[:1] != ["default"] or re.search(r"\bdev\s+\S+", line):
                continue
            following = route_lines[i + 1] if i + 1 < len(route_lines) else ""
            if not (following[:1].isspace() and following.split()[:1] == ["nexthop"]):
                raise ValueError(
                    f"A default route does not name an interface ({line.strip()!r}), so the WAN interface "
                    f"cannot be detected safely. Pass --wan <interface>."
                )
        for m in re.finditer(r"\bdev\s+(\S+)", res.stdout):
            if m.group(1) not in devices:
                devices.append(m.group(1))
    if len(devices) != 1:
        found = ", ".join(devices) if devices else "none"
        raise ValueError(
            f"WAN interface not auto-detected: expected exactly one default-route interface, found {found}. "
            f"Pass --wan <interface>, and run fix once per uplink if there is more than one."
        )
    logger.warning(f"[!] WAN interface auto-detected as '{devices[0]}' (the only default-route interface). "
                   f"Pass --wan to set it explicitly.")
    return devices[0]


def resolve_wan(explicit: "str | None", configured: "str | None") -> str:
    return explicit or configured or auto_detect_wan_interface()


def validate_wan_interface(wan: str):
    if not isinstance(wan, str) or not WAN_NAME_RE.fullmatch(wan) or wan in (".", ".."):
        raise ValueError(f"Safety Error: WAN interface name {wan!r} is not a valid interface name "
                         f"(letters, digits, '_', '.', '-'; at most 15 characters).")
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        names = []
    if wan not in names:
        raise ValueError(f"Safety Error: WAN interface '{wan}' does not exist in /sys/class/net/. Verify interface name.")


def default_gateways() -> "tuple[list, bool]":
    gateways = []
    known = True
    for cmd in (["ip", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]):
        try:
            res = _proc(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            known = False
            continue
        for m in re.finditer(r"\bvia\s+(?:inet6?\s+)?(\S+)", res.stdout):
            try:
                addr = ipaddress.ip_address(m.group(1).split("%", 1)[0])
            except ValueError:
                known = False
                continue
            if addr not in gateways:
                gateways.append(addr)
    return gateways, known


def host_addresses() -> "tuple[list, bool]":
    try:
        res = _proc(["ip", "-o", "addr", "show"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return [], False
    found = []
    for m in re.finditer(r"\binet6?\s+([0-9A-Fa-f:.]+)", res.stdout):
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if addr not in found:
            found.append(addr)
    return found, True


def normalise_fix_target(ip: str) -> str:
    if "%" in ip:
        raise ValueError(f"fix target {ip} is a link-local address with a zone; it is not routed through the gateway, "
                         f"so there is nothing to block.")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"fix target {ip!r} is not a valid IP address.")
    if getattr(addr, "ipv4_mapped", None) is not None:
        raise ValueError(f"fix target {ip} is in IPv4-mapped IPv6 form; a rule for that form would not match the "
                         f"controller's traffic. Pass the plain IPv4 address.")
    return str(addr)


def ipv6_enabled() -> bool:
    return os.path.exists("/proc/net/if_inet6") or not os.path.isdir("/proc/net")


def host_forwards(v6: bool) -> "bool | None":
    path = "/proc/sys/net/ipv6/conf/all/forwarding" if v6 else "/proc/sys/net/ipv4/ip_forward"
    try:
        return Path(path).read_text().strip() == "1"
    except Exception:
        return None


def is_ipv4_mapped(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return getattr(addr, "ipv4_mapped", None) is not None


def is_local_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_private or addr.is_loopback or addr.is_link_local


def resolve_target(target: str, max_hosts: int) -> "tuple[list[str], bool]":
    target = target.strip()
    if not target:
        raise ValueError("An empty target was given. Pass an address, a range or a hostname.")
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
next_request_slot = 0.0


def enforce_rate_limit(rate_limit: float):
    global next_request_slot
    if rate_limit <= 0:
        return
    interval = 1.0 / rate_limit
    with rate_limit_lock:
        now = time.monotonic()
        slot = max(now, next_request_slot)
        next_request_slot = slot + interval
    wait = slot - now
    if wait > 0:
        stop_scan.wait(wait)


def _connect(host: str, port: int, timeout: float):
    if port in SSL_PORTS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


class ProbeDeadline(Exception):
    pass


class ProbeNoAnswer(Exception):
    pass


stop_scan = threading.Event()


def _abort_connection(conn):
    sock = getattr(conn, "sock", None)
    if sock is None:
        return
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass


def _fetch(host: str, port: int, path: str, timeout: float, limit: int, body_statuses=None) -> "tuple[int, bytes]":
    deadline = max(PROBE_DEADLINE_MIN, 3.0 * timeout)
    conn = _connect(host, port, timeout)
    done = threading.Event()
    expired = threading.Event()

    def watchdog():
        end = time.monotonic() + deadline
        while True:
            remaining = end - time.monotonic()
            if done.wait(max(0.0, min(0.2, remaining))):
                return
            if remaining <= 0 or stop_scan.is_set():
                break
        expired.set()
        _abort_connection(conn)
        while not done.wait(0.2):
            _abort_connection(conn)

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        try:
            conn.connect()
        except ConnectionRefusedError:
            raise
        except OSError as e:
            unanswered = (isinstance(e, (TimeoutError, socket.timeout))
                          or getattr(e, "errno", None) in NO_ANSWER_ERRNOS
                          or getattr(e, "winerror", None) in NO_ANSWER_WINERRORS)
            if unanswered and getattr(conn, "sock", None) is None and not expired.is_set():
                raise ProbeNoAnswer(f"{host}:{port} did not answer") from None
            raise
        conn.request("GET", path)
        resp = conn.getresponse()
        status = resp.status
        body = b""
        if body_statuses is None or status in body_statuses:
            while len(body) < limit:
                chunk = resp.read1(min(8192, limit - len(body)))
                if not chunk:
                    break
                body += chunk
        if expired.is_set():
            raise ProbeDeadline(f"{host}:{port} exceeded the {deadline:.0f}s probe deadline")
        return status, body
    except (ProbeDeadline, ProbeNoAnswer):
        raise
    except Exception:
        if expired.is_set():
            raise ProbeDeadline(f"{host}:{port} exceeded the {deadline:.0f}s probe deadline") from None
        raise
    finally:
        done.set()
        conn.close()


def identify_controller(body: bytes) -> "tuple[str, str]":
    for fp in DANFOSS_FINGERPRINTS:
        if fp in body:
            return "Danfoss StoreView", fp.decode("ascii")
    for fp in DIXELL_FINGERPRINTS:
        if fp in body:
            return "Dixell XWEB Pro", fp.decode("ascii")
    return "", ""


PORT_OK = "ok"
PORT_REFUSED = "refused"
PORT_SILENT = "silent"
PORT_ERROR = "error"


def probe_port(host: str, port: int, timeout: float, rate_limit: float) -> "tuple[bytes | None, str, str]":
    enforce_rate_limit(rate_limit)
    try:
        _status, body = _fetch(host, port, "/", timeout, 65536)
    except ConnectionRefusedError:
        return None, "", PORT_REFUSED
    except ProbeNoAnswer:
        return None, "", PORT_SILENT
    except ProbeDeadline as e:
        logger.debug(f"probe deadline: {e}")
        return None, "", PORT_ERROR
    except Exception:
        return None, "", PORT_ERROR
    ctype, _match = identify_controller(body)
    return body, ctype, PORT_OK


def http_probe(host: str, port: int, timeout: float, rate_limit: float) -> "tuple[bytes | None, str, bool]":
    body, ctype, state = probe_port(host, port, timeout, rate_limit)
    return body, ctype, state in (PORT_SILENT, PORT_ERROR)


def check_auth_endpoint(host: str, port: int, ctype: str, timeout: float, rate_limit: float) -> str:
    enforce_rate_limit(rate_limit)
    endpoint = DANFOSS_VULN_ENDPOINT if "Danfoss" in ctype else DIXELL_VULN_ENDPOINT
    try:
        code, body = _fetch(host, port, endpoint, timeout, 2048, body_statuses=(200,))
    except Exception:
        return AUTH_UNKNOWN
    if code == 200:
        head = body.lstrip().lower()
        if not head or head.startswith(b"<!doctype html") or head.startswith(b"<html"):
            return AUTH_UNKNOWN
        return AUTH_OPEN
    if code in (401, 403, 404):
        return AUTH_CLOSED
    return AUTH_UNKNOWN


def scan_host(ip: str, timeout: float, rate_limit: float) -> "dict | None":
    found = None
    errored_ports = []
    silent_ports = []
    for port in PORTS:
        if stop_scan.is_set():
            errored_ports.append(port)
            continue
        body, ctype, state = probe_port(ip, port, timeout, rate_limit)
        if state in (PORT_SILENT, PORT_ERROR):
            errored_ports.append(port)
            if state == PORT_SILENT:
                silent_ports.append(port)
            continue
        if not ctype:
            continue
        auth = check_auth_endpoint(ip, port, ctype, timeout, rate_limit)
        rank = {AUTH_OPEN: 3, AUTH_UNKNOWN: 2, AUTH_CLOSED: 1}
        if found is None or rank[auth] > rank[found["auth"]]:
            found = {
                "ip": ip, "port": port, "controller": ctype, "match": identify_controller(body)[1], "auth": auth,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "body_snippet": (clean_text(body[:150].decode('latin1', errors='ignore'))
                                 if (body and is_local_address(ip)) else "")
            }
    if found is not None:
        if errored_ports and found["auth"] != AUTH_OPEN:
            found["auth"] = AUTH_UNKNOWN
            found["partial_probe"] = errored_ports
        return found
    if errored_ports:
        return {"ip": ip, "port": None, "controller": "", "auth": AUTH_UNKNOWN,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "body_snippet": "", "probe_error": True,
                "silent": len(silent_ports) == len(PORTS) and not stop_scan.is_set()}
    return None


def scan_targets(targets, workers, timeout, rate_limit, max_hosts, authorized=False) -> "tuple[list[dict], dict]":
    all_ips = []
    meta = {"unresolved": [], "total": 0, "probe_errors": 0, "silent": 0}
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
    stop_scan.clear()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {pool.submit(scan_host, ip, timeout, rate_limit): ip for ip in all_ips}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if done % 10 == 0 or done == len(all_ips):
                logger.info(f"    Scanned {done}/{len(all_ips)} hosts...")
            r = fut.result()
            if not r:
                continue
            if r.get("probe_error") and not r["controller"]:
                if r.get("silent"):
                    meta["silent"] += 1
                else:
                    meta["probe_errors"] += 1
                continue
            results.append(r)
            if r["auth"] == AUTH_OPEN:
                tag = f"{colors.FAIL}AUTH ENDPOINT OPEN (likely vulnerable){colors.ENDC}"
            elif r["auth"] == AUTH_UNKNOWN:
                tag = f"{colors.WARNING}EXPOSED (auth state unknown){colors.ENDC}"
            else:
                tag = f"{colors.WARNING}EXPOSED (auth endpoint closed){colors.ENDC}"
            logger.info(f"  [FOUND] {r['ip']}:{r['port']} ({r['controller']}; matched '{r.get('match', '')}') -> {tag}")
    except BaseException:
        stop_scan.set()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return results, meta


def nothing_answered(meta: dict) -> bool:
    return meta.get("total", 0) > 0 and meta.get("silent", 0) >= meta["total"]


def scan_incomplete(meta: dict, silent_ok: bool) -> bool:
    silent = meta.get("silent", 0)
    return bool(meta["unresolved"] or meta["probe_errors"] or (silent and (not silent_ok or nothing_answered(meta))))


def _safe_write_text(path: Path, text: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        fh = os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise
    with fh:
        fh.write(text.encode("utf-8"))


def backup_existing_rules(backend: str):
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = d / f"backup-{backend}-{date_str}.rules"
    try:
        if backend == "nftables":
            res = _proc(["nft", "list", "ruleset"], stdout=subprocess.PIPE, text=True, check=True)
            _safe_write_text(backup_file, res.stdout)
        elif backend == "iptables":
            out = []
            for tool in ("iptables-save", "ip6tables-save"):
                try:
                    out.append(_proc([tool], stdout=subprocess.PIPE, text=True, check=True).stdout)
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
            res = _proc(["nft", "list", "table"] + NFT_TABLE, stdout=subprocess.PIPE, text=True, check=True)
            out = data_dir() / "danfoss_shield.nft"
            _safe_write_text(out, res.stdout)
            hint = f"add 'include \"{out}\"' to /etc/nftables.conf and enable nftables.service"
        else:
            dump = []
            for tool in ("iptables-save", "ip6tables-save"):
                try:
                    dump.append(_proc([tool], stdout=subprocess.PIPE, text=True, check=True).stdout)
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
    return ["iifname", f'"{wan}"', fam, "daddr", ip, "ct", "state", "new", "counter", "drop", "comment", RULE_TAG]


def ipt_rule_args(ip: str, wan: str) -> "list[str]":
    return ["-i", wan, "-d", ip, "-m", "conntrack", "--ctstate", "NEW",
            "-m", "comment", "--comment", RULE_TAG, "-j", "DROP"]


def nft_table_state() -> str:
    try:
        res = _proc(["nft", "list", "tables"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError:
        return "error"
    if res.returncode != 0:
        return "error"
    wanted = "table " + " ".join(NFT_TABLE)
    return "present" if any(line.strip() == wanted for line in res.stdout.splitlines()) else "absent"


def check_rule_exists(backend: str, ip: str, wan: str) -> bool:
    try:
        if backend == "iptables":
            tool = "ip6tables" if ":" in ip else "iptables"
            return _proc([tool, "-C", "FORWARD"] + ipt_rule_args(ip, wan) + IPT_WAIT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if backend == "nftables":
            res = _proc(["nft", "list", "chain"] + NFT_TABLE + [NFT_CHAIN],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if res.returncode != 0:
                return False
            for line in res.stdout.splitlines():
                tokens = line.split()
                if f'"{RULE_TAG}"' not in tokens or f'"{wan}"' not in tokens:
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
    try:
        res = _proc(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except TimeoutError:
        logger.error(f"[-] Command did not finish in {CMD_TIMEOUT:.0f} s and was stopped: {' '.join(cmd)}. "
                     f"Its effect is unknown: check with `fix --rollback --dry-run`.")
        return False
    except OSError as e:
        if not quiet_fail:
            logger.error(f"[-] Command could not be started: {' '.join(cmd)}: {type(e).__name__}")
        return False
    if res.returncode != 0 and not quiet_fail:
        logger.error(f"[-] Command failed: {' '.join(cmd)}: {res.stderr.strip()}")
    return res.returncode == 0


def remove_iptables_tagged(chains, dry_run) -> "tuple[int, int]":
    removed = failed = 0
    for tool in ("iptables", "ip6tables"):
        if tool == "ip6tables" and not ipv6_enabled():
            logger.debug("IPv6 is not enabled on this host; skipping ip6tables")
            continue
        for chain in chains:
            try:
                res = _proc([tool, "-S", chain] + IPT_WAIT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=True)
            except FileNotFoundError:
                logger.debug(f"{tool} not installed; skipping {chain}")
                continue
            except (OSError, subprocess.CalledProcessError) as e:
                detail = (getattr(e, "stderr", "") or "").strip() or type(e).__name__
                logger.error(f"[-] Could not list {tool} chain {chain} ({detail}); "
                             f"cannot confirm its danfoss-shield rules are gone.")
                failed += 1
                continue
            for line in res.stdout.splitlines():
                if RULE_TAG not in line or not line.startswith("-A "):
                    continue
                try:
                    args = shlex.split(line)
                except ValueError:
                    continue
                if "--comment" not in args or args.index("--comment") + 1 >= len(args) \
                        or args[args.index("--comment") + 1] != RULE_TAG:
                    continue
                args[0] = "-D"
                if _run([tool] + args + IPT_WAIT, dry_run):
                    removed += 1
                else:
                    failed += 1
    return removed, failed


def remove_legacy_input_rules(backend: str, dry_run: bool):
    if backend == "nftables":
        try:
            exists = _proc(["nft", "list", "chain"] + NFT_TABLE + ["input"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        except OSError:
            exists = False
        if exists:
            logger.info("[*] Removing ineffective rules from the nftables 'input' chain.")
            _run(["nft", "flush", "chain"] + NFT_TABLE + ["input"], dry_run)
            _run(["nft", "delete", "chain"] + NFT_TABLE + ["input"], dry_run)
    elif backend == "iptables":
        n, _ = remove_iptables_tagged(["INPUT"], dry_run)
        if n:
            logger.info(f"[*] Removed {n} ineffective INPUT rule(s).")


def rollback_all(dry_run: bool) -> dict:
    summary = {"removed": 0, "failed": 0}
    if not dry_run and not is_root():
        raise NeedsRoot("Rollback requires root privileges (run with sudo).")
    have_nft = detect_firewall_backend("auto") == "nftables" or _tool_present("nft")
    have_ipt = _tool_present("iptables")
    summary["backends"] = int(have_nft) + int(have_ipt)

    if have_nft:
        if dry_run:
            logger.info("[DRY-RUN] nft delete table " + " ".join(NFT_TABLE) + " (if present)")
        else:
            state = nft_table_state()
            if state == "present":
                if _run(["nft", "delete", "table"] + NFT_TABLE, dry_run):
                    logger.info("[+] Removed nftables table inet danfoss_shield")
                    summary["removed"] += 1
                else:
                    summary["failed"] += 1
            elif state == "absent":
                logger.info("[*] No nftables table inet danfoss_shield present.")
            else:
                logger.error("[-] Could not list nftables tables; cannot confirm the danfoss_shield table is gone.")
                summary["failed"] += 1
    if have_ipt:
        r, f = remove_iptables_tagged(["FORWARD", "INPUT"], dry_run)
        summary["removed"] += r
        summary["failed"] += f
    if not have_nft and not have_ipt:
        logger.warning("[!] Neither nft nor iptables found; nothing could be rolled back.")
    saved = [str(p) for p in (data_dir() / "danfoss_shield.nft", data_dir() / "danfoss_shield.iptables") if p.exists()]
    summary["saved_files"] = saved
    if saved:
        logger.warning(f"[!] Rollback removes live rules only. Saved rule file(s) remain: {', '.join(saved)}. "
                       f"If you added them to boot persistence, remove that yourself or the rules return at reboot.")
    return summary


def _tool_present(tool: str) -> bool:
    try:
        return _proc([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        return False


@contextlib.contextmanager
def firewall_lock(dry_run: bool):
    if dry_run or not is_root():
        yield
        return
    try:
        import fcntl
    except ImportError:
        yield
        return
    lock_path = data_dir() / "fix.lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | O_NOFOLLOW, 0o600)
    except OSError as e:
        logger.warning(f"[!] Could not create the run lock {lock_path} ({e}); continuing without it. "
                       f"Make sure no other fix or rollback is running.")
        yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("Another danfoss-shield fix or rollback is running on this host; "
                               "wait for it to finish and run this again.") from None
        yield
    finally:
        os.close(fd)


def apply_firewall_rules(ips, wan, backend, dry_run, force, backup, routed=False) -> dict:
    summary = {"applied": 0, "existing": 0, "skipped": 0}
    if backend not in ("nftables", "iptables"):
        raise ValueError("No supported firewall backend found (need nft or iptables).")
    if not dry_run and not is_root():
        raise NeedsRoot("Firewall modification requires root privileges (run with sudo).")

    validate_wan_interface(wan)
    ips = list(dict.fromkeys(normalise_fix_target(ip) for ip in ips))

    non_local = [ip for ip in ips if not is_local_address(ip)]
    if non_local and not (force or routed):
        sample = ", ".join(non_local[:5]) + (" ..." if len(non_local) > 5 else "")
        raise ValueError(
            f"fix targets must be the controller's INTERNAL address. These look public: {sample}. "
            f"On a gateway, DNAT rewrites a port-forwarded address before FORWARD, so the rule would "
            f"never match. Pass the LAN address (or use `fix --all <lan>/24`). If the controller really has "
            f"a routed public address with no port-forward, pass --routed."
        )
    if non_local and routed:
        logger.warning(f"[!] {len(non_local)} routed public target(s) accepted because of --routed. "
                       f"All other safety checks stay on.")

    own, own_known = host_addresses()
    mine = [ip for ip in ips if ipaddress.ip_address(ip) in own]
    if mine:
        raise ValueError(f"fix target {', '.join(mine)} is an address of this host itself. These rules sit in the "
                         f"forwarding path and never see traffic for the host, so nothing would be blocked. "
                         f"Pass the controller's own address.")

    gateways, gateways_known = default_gateways()
    if not own_known:
        logger.warning("[!] WARNING: this host's own addresses could not be read, so the check that a target is "
                       "not the gateway itself could not run.")
    if not gateways_known:
        logger.warning("[!] WARNING: the default routes could not be read, so the check that stops you "
                       "blocking your own gateway could not run fully. Verify the targets yourself.")
    hit = [ip for ip in ips if ipaddress.ip_address(ip) in gateways]
    if hit:
        if not force:
            raise ValueError(f"Safety Abort: Target list includes a default gateway address ({', '.join(hit)}). "
                             f"Use --force to override.")
        logger.warning(f"[!] WARNING: Overriding gateway protection for {', '.join(hit)} due to --force flag.")

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
        if not dry_run and check_rule_exists(backend, ip, wan) and not force:
            summary["existing"] += 1
            continue
        if backend == "nftables":
            cmd = ["nft", "add", "rule"] + NFT_TABLE + [NFT_CHAIN] + nft_rule_args(ip, wan)
        else:
            tool = "ip6tables" if ":" in ip else "iptables"
            cmd = [tool, "-I", "FORWARD"] + ipt_rule_args(ip, wan) + IPT_WAIT
        if _run(cmd, dry_run):
            summary["applied"] += 1
        else:
            summary["skipped"] += 1

    if not dry_run and summary["applied"]:
        save_applied_rules(backend)
    return summary


def _shodan_search(api_key: str, query: str) -> "dict | None":
    url = f"https://api.shodan.io/shodan/host/search?key={urllib.parse.quote(api_key)}&query={urllib.parse.quote(query)}"
    logger.info("[*] Querying Shodan API...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"danfoss-shield/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(SHODAN_MAX_BYTES + 1)
        if len(raw) > SHODAN_MAX_BYTES:
            logger.error(f"[-] Shodan API answer is larger than {SHODAN_MAX_BYTES // (1024 * 1024)} MB; refusing to parse it.")
            return None
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.error(f"[-] Shodan API query failed: {type(e).__name__}")
        return None
    if not isinstance(data, dict) or data.get("error") or not isinstance(data.get("matches"), list):
        logger.error("[-] Shodan API did not return a valid result set (treating as failure).")
        return None
    return data


def _shodan_matches(data: dict) -> "list[dict]":
    results = []
    for m in data["matches"]:
        if not isinstance(m, dict):
            continue
        banner = m.get("data", "")
        banner_bytes = banner.encode('latin1', errors='ignore') if isinstance(banner, str) else b""
        ctype = "Unknown"
        if any(fp in banner_bytes for fp in DANFOSS_FINGERPRINTS):
            ctype = "Danfoss StoreView"
        elif any(fp in banner_bytes for fp in DIXELL_FINGERPRINTS):
            ctype = "Dixell XWEB Pro"
        port = m.get("port")
        results.append({"ip": clean_text(str(m.get("ip_str", "")), 64),
                        "port": port if isinstance(port, int) and not isinstance(port, bool) else None,
                        "controller": ctype,
                        "org": clean_text(str(m.get("org") or "Unknown"))})
    return results


def query_shodan(api_key: str, query: str) -> "tuple[list[dict] | None, bool]":
    data = _shodan_search(api_key, query)
    if data is None:
        return None, False
    return _shodan_matches(data), True


def shodan_scope_net(net_text: str, authorized: bool):
    try:
        net = ipaddress.ip_network(str(net_text).strip(), strict=False)
    except ValueError:
        raise ValueError(f"--net {net_text!r} is not a valid network. Give your own public range in CIDR form, "
                         f"such as a /28 or /29.")
    if net.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(f"--net {net} has {net.num_addresses} addresses, over the cap of {MAX_SCAN_HOSTS}. Narrow the range.")
    if (net.is_private or net.is_loopback or net.is_link_local or net.is_multicast
            or net.is_reserved or net.is_unspecified):
        raise ValueError(f"--net {net} is not a public range. Shodan only indexes public addresses; "
                         f"pass the public range you own, or use `scan` for an internal network.")
    if not authorized:
        raise ValueError(f"--net {net} is a public range. Looking up systems you do not own or administer is not "
                         f"what this tool is for. If the range is yours, re-run with --authorized.")
    return net


def shodan_scope_query(net_text: str, authorized: bool) -> str:
    net = shodan_scope_net(net_text, authorized)
    return f"net:{net} port:{','.join(str(p) for p in PORTS)}"


def shodan_lookup(api_key: str, net_text: str, authorized: bool) -> "tuple[list[dict] | None, bool, bool, int]":
    net = shodan_scope_net(net_text, authorized)
    data = _shodan_search(api_key, f"net:{net} port:{','.join(str(p) for p in PORTS)}")
    if data is None:
        return None, False, False, 0
    results = []
    outside = 0
    for r in _shodan_matches(data):
        try:
            inside = ipaddress.ip_address(r["ip"]) in net
        except ValueError:
            inside = False
        if inside:
            results.append(r)
        else:
            outside += 1
    total = data.get("total")
    truncated = isinstance(total, int) and not isinstance(total, bool) and total > len(data["matches"])
    return results, True, truncated, outside


def _exec_start(subnet: str, scans_dir: Path) -> "list[str]":
    out = scans_dir / "scan-latest.json"
    return [sys.executable, os.path.abspath(sys.argv[0]), "--quiet", "scan", subnet, "--silent-ok", "--output", str(out)]


def systemd_exec_line(argv: "list[str]") -> str:
    return " ".join(shlex.quote(a) for a in argv).replace("%", "%%").replace("$", "$$")


def install_systemd_timer(scan_subnet: str):
    try:
        ipaddress.ip_network(scan_subnet, strict=False)
    except ValueError:
        logger.error(f"[-] Config subnet '{scan_subnet}' is not a valid network; refusing to write the unit.")
        sys.exit(EXIT_ERROR)

    target_dir = Path.home() / ".config" / "systemd" / "user"
    scans_dir = data_dir() / "scans"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        scans_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f"[-] Could not create the unit or scan directory ({e}); the timer was not installed.")
        sys.exit(EXIT_ERROR)

    argv = _exec_start(scan_subnet, scans_dir)

    ok, err = _parse_check(argv[2:])
    if not ok:
        logger.error(f"[-] Generated scan command does not parse ({err}); not writing the timer.")
        sys.exit(EXIT_ERROR)

    exec_start = systemd_exec_line(argv)
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
    try:
        _safe_write_text(target_dir / "danfoss-shield.service", service_content)
        _safe_write_text(target_dir / "danfoss-shield.timer", timer_content)
    except OSError as e:
        logger.error(f"[-] Could not write the systemd units to {target_dir} ({e}); the timer was not installed.")
        sys.exit(EXIT_ERROR)
    logger.info(f"[+] Installed systemd units to {target_dir}")
    logger.info("    systemctl --user daemon-reload && systemctl --user enable --now danfoss-shield.timer")


def install_suricata_rules() -> bool:
    rule_dir = Path("/etc/suricata/rules")
    if not is_root():
        logger.warning("[!] Not running as root; writing Suricata rules to the data directory instead of /etc/suricata/rules.")
        rule_dir = data_dir() / "rules"
    rule_file = rule_dir / SURICATA_RULE_FILE
    rule_content = ('# danfoss-shield detection rules: requests to the controller auth endpoints (plain HTTP only)\n'
                    'alert tcp any any -> any [80,443,8080,8443,3080,3443] (msg:"DANFOSS-SHIELD Danfoss StoreView auth endpoint request"; content:"/xml.cgi?action=getauth"; fast_pattern; sid:9900001; rev:2;)\n'
                    'alert tcp any any -> any [80,443,8080,8443,3080,3443] (msg:"DANFOSS-SHIELD Dixell XWEB command endpoint request"; content:"/cgi-bin/dixell.cgi"; fast_pattern; sid:9900002; rev:2;)\n')
    try:
        rule_dir.mkdir(parents=True, exist_ok=True)
        _safe_write_text(rule_file, rule_content)
    except OSError as e:
        logger.error(f"[-] Failed to write Suricata rules to {rule_file}: {e}")
        return False
    logger.info(f"[+] Suricata detection rules written to {rule_file}")
    if is_root():
        try:
            rc = _proc(["systemctl", "reload", "suricata"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        except OSError as e:
            logger.warning(f"[!] Could not ask Suricata to reload ({type(e).__name__}).")
        else:
            if rc == 0:
                logger.info("[*] Asked Suricata to reload (systemctl reload suricata).")
            else:
                logger.warning(f"[!] systemctl reload suricata returned {rc}.")
    logger.warning(f"[!] The rules are written but NOT confirmed loaded. Suricata only loads files listed under "
                   f"rule-files in suricata.yaml: add '{rule_file.name}' there and check with `suricata -T`. "
                   f"They match plain HTTP only (not TLS traffic) and also alert on this tool's own scans.")
    return True


def remove_suricata_rules() -> bool:
    ok = True
    for path in [Path("/etc/suricata/rules") / SURICATA_RULE_FILE, data_dir() / "rules" / SURICATA_RULE_FILE]:
        try:
            if path.exists():
                path.unlink()
                logger.info(f"[+] Removed Suricata rule file: {path}")
        except OSError as e:
            logger.error(f"[-] Could not remove Suricata rule file {path}: {e}")
            ok = False
    return ok


def csv_safe(value):
    if not isinstance(value, str):
        return value
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r', '\n'):
        return "'" + value
    return value


def export_results(results, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        _safe_write_text(path, json.dumps(results, indent=2))
    elif path.suffix == ".csv":
        keys = list(dict.fromkeys(k for r in results for k in r)) or ["ip", "port", "controller", "auth", "timestamp"]
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


class ShieldParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser(cfg) -> argparse.ArgumentParser:
    parser = ShieldParser(
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
    timeout_type = bounded_number(float, TIMEOUT_RANGE, "--timeout")
    silent_help = ("Do not fail the run for addresses that never answered on any port (they are still counted "
                   "and printed). A controller behind a filter that drops probes would be missed.")
    p_scan.add_argument("-w", "--workers", type=bounded_number(int, WORKERS_RANGE, "--workers"), default=int(cfg["workers"]))
    p_scan.add_argument("--timeout", type=timeout_type, default=float(cfg["timeout"]))
    p_scan.add_argument("--rate-limit", type=bounded_number(float, RATE_RANGE, "--rate-limit"), default=float(cfg["rate_limit"]),
                        help="Requests per second across all workers (0 = no limit)")
    p_scan.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")
    p_scan.add_argument("--silent-ok", action="store_true", help=silent_help)
    p_scan.add_argument("-o", "--output", help="Output file (.json, .csv, .txt)")

    p_check = sub.add_parser("check", help="Check specific IPs or hostnames you own", allow_abbrev=False)
    p_check.add_argument("targets", nargs="+")
    p_check.add_argument("--timeout", type=timeout_type, default=float(cfg["timeout"]))
    p_check.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")
    p_check.add_argument("--silent-ok", action="store_true", help=silent_help)
    p_check.add_argument("-o", "--output", help="Output file")

    p_fix = sub.add_parser("fix", help="Block new WAN connections to controllers (run on the gateway)", allow_abbrev=False)
    p_fix.add_argument("targets", nargs="*")
    p_fix.add_argument("--all", action="store_true", help="Scan the targets and block every controller found")
    p_fix.add_argument("--wan", default=None,
                       help="WAN interface (default: config value; auto-detected only when exactly one default-route interface exists)")
    p_fix.add_argument("--dry-run", action="store_true", help="Print rules without applying")
    p_fix.add_argument("--force", action="store_true", help="Re-add existing rules / bypass safety locks")
    p_fix.add_argument("--routed", action="store_true",
                       help="Accept a controller's routed public address as a target (no port-forward in front of it); "
                            "needs --authorized, keeps every other safety check on")
    p_fix.add_argument("--silent-ok", action="store_true", help="With --all: " + silent_help)
    p_fix.add_argument("--rollback", action="store_true", help="Remove all live danfoss-shield rules (both backends)")
    p_fix.add_argument("--backup", action="store_true", default=True, help="Backup existing rules before applying (default)")
    p_fix.add_argument("--no-backup", action="store_false", dest="backup", help="Skip the rule backup")
    p_fix.add_argument("--authorized", action="store_true", help="Confirm you own/are authorized to test public targets")

    p_shod = sub.add_parser("shodan", help="Look up internet exposure of your own public range via the Shodan API (no probing, no blocking)", allow_abbrev=False)
    p_shod.add_argument("--api-key", default=os.environ.get("SHODAN_API_KEY"),
                        help="Shodan API key (prefer the SHODAN_API_KEY env var; a flag also lands in shell history)")
    p_shod.add_argument("--net", required=True, help="Your own public range in CIDR form; the lookup is limited to it")
    p_shod.add_argument("--authorized", action="store_true", help="Confirm you own/administer the range given in --net")
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


def _report_error(message: str):
    if logger.handlers:
        logger.error(message)
    else:
        sys.stderr.write(message + "\n")


def main():
    check_dependencies()
    cfg = load_config()
    _, _, _, _, parser = build_parser(cfg)
    args = parser.parse_args()
    try:
        _dispatch(args, cfg, parser)
    except KeyboardInterrupt:
        stop_scan.set()
        message = "[-] Interrupted."
        if getattr(args, "cmd", None) == "fix" and not getattr(args, "dry_run", False):
            message += (" If rules were being applied or removed, the firewall may be in a partial state: "
                        "run `fix --rollback --dry-run` to see what is there and `fix --rollback` to remove it.")
        _report_error(message)
        sys.exit(EXIT_ERROR)
    except NeedsRoot as e:
        _report_error(f"[-] Error: {e}")
        sys.exit(EXIT_MISSING_DEPS)
    except (ValueError, RuntimeError, OSError) as e:
        _report_error(f"[-] Error: {e}")
        sys.exit(EXIT_ERROR)


def _dispatch(args, cfg, parser):
    setup_logging(args.verbose, args.quiet, args.no_color)

    if args.install_timer:
        install_systemd_timer(cfg["subnet"])
        sys.exit(EXIT_OK)
    if args.install_suricata:
        sys.exit(EXIT_OK if install_suricata_rules() else EXIT_ERROR)
    if args.remove_suricata:
        sys.exit(EXIT_OK if remove_suricata_rules() else EXIT_ERROR)
    if not args.cmd:
        parser.print_help()
        sys.exit(EXIT_OK)

    logger.info("[i] danfoss-shield is a defensive tool - use only on networks/hosts you own or are "
                "authorized to test. MIT, no warranty. See LICENSE & README.")

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
        if meta.get("silent"):
            note = "state unknown"
            if args.silent_ok and not nothing_answered(meta):
                note = "not counted as a failure because of --silent-ok"
            print(f"Addresses that never answered on any port: {meta['silent']} ({note})")
        if nothing_answered(meta):
            print("No address answered at all - wrong range, or no network? This counts as incomplete even with --silent-ok.")

        if args.output:
            export_results(results, args.output)

        if open_count > 0:
            sys.exit(EXIT_VULN_FOUND)
        if scan_incomplete(meta, args.silent_ok) or unknown_count:
            sys.exit(EXIT_ERROR)
        sys.exit(EXIT_OK)

    elif args.cmd == "fix":
        backend = detect_firewall_backend(args.backend)

        if args.rollback:
            with firewall_lock(args.dry_run):
                summary = rollback_all(args.dry_run)
            print(f"\nRolled back: removed {summary['removed']}, failed {summary['failed']}")
            if not summary["removed"] and not summary["failed"]:
                print("Nothing was removed: no live danfoss-shield rules were found.")
            sys.exit(EXIT_ERROR if (summary["failed"] or summary.get("backends", 0) == 0) else EXIT_OK)

        ips_to_block = []
        fix_partial = False
        if args.all:
            scan_list = args.targets if args.targets else [cfg["subnet"]]
            scan_res, meta = scan_targets(scan_list, 30, 3.0, 20.0, MAX_FIX_HOSTS, args.authorized)
            for r in scan_res:
                if r["controller"]:
                    ips_to_block.append(r["ip"])
                    logger.info(f"[*] Will block {r['ip']} ({r['controller']}; matched '{r.get('match', '')}' "
                                f"on port {r['port']})")
            if meta.get("silent"):
                note = "counted as incomplete"
                if args.silent_ok and not nothing_answered(meta):
                    note = "ignored for the exit code because of --silent-ok"
                logger.warning(f"[!] {meta['silent']} address(es) never answered on any port ({note}).")
            if nothing_answered(meta):
                logger.warning("[!] No address answered at all - wrong range, or no network? "
                               "This counts as incomplete even with --silent-ok.")
            if scan_incomplete(meta, args.silent_ok):
                fix_partial = True
                logger.warning(f"[!] Scan was partial (probe errors: {meta['probe_errors']}, "
                               f"unresolved: {len(meta['unresolved'])}, silent: {meta.get('silent', 0)}); "
                               f"some controllers may be left unblocked.")
        elif args.targets:
            unresolved = []
            for t in args.targets:
                ips, ok = resolve_target(t, MAX_FIX_HOSTS)
                if not ok:
                    unresolved.append(t)
                ips_to_block.extend(ips)
            if unresolved:
                fix_partial = True
                logger.warning(f"[!] {len(unresolved)} target(s) did not resolve and were NOT blocked: "
                               f"{', '.join(unresolved[:5])}")
            require_authorized(ips_to_block, args.authorized)
        else:
            logger.error("[-] Error: specify targets, use --all with targets, or use --rollback")
            sys.exit(EXIT_ERROR)

        ips_to_block = list(dict.fromkeys(ips_to_block))
        mapped = [ip for ip in ips_to_block if is_ipv4_mapped(ip)]
        if mapped:
            raise ValueError(f"fix targets in IPv4-mapped IPv6 form are refused ({', '.join(mapped[:5])}): "
                             f"a rule for that form would not match the controller's traffic. "
                             f"Pass the plain IPv4 address.")
        if not ips_to_block:
            if fix_partial:
                logger.error("[-] Nothing was blocked, and the scan or name lookup did not complete: "
                             "controllers may still be exposed.")
                sys.exit(EXIT_ERROR)
            logger.info("[*] No target IPs identified for blocking.")
            sys.exit(EXIT_OK)

        wan = resolve_wan(args.wan, cfg.get("wan"))
        logger.info(f"[*] Backend: {backend} | WAN Interface: {wan}")
        with firewall_lock(args.dry_run):
            summary = apply_firewall_rules(ips_to_block, wan, backend, args.dry_run, args.force, args.backup,
                                           routed=args.routed)
        v6_count = sum(1 for ip in ips_to_block if ":" in ip)
        print("\n=== FIX SUMMARY ===")
        print(f"Target IPs:        {len(ips_to_block)} (IPv4 {len(ips_to_block) - v6_count}, IPv6 {v6_count})")
        print(f"Newly applied:     {summary['applied']}")
        print(f"Already existing:  {summary['existing']}")
        print(f"Skipped (failed):  {summary['skipped']}")
        print("Note: only NEW inbound connections arriving on the WAN interface are dropped. Sessions that are "
              "already open, and connections a controller opens outward, are not cut.")
        if args.all:
            print("Note: a sweep of an IPv4 range does not find IPv6 addresses the same controllers may have.")
        sys.exit(EXIT_ERROR if (summary["skipped"] or fix_partial) else EXIT_OK)

    elif args.cmd == "shodan":
        if not args.api_key:
            logger.error("[-] Error: Shodan API key required (--api-key or SHODAN_API_KEY env var).")
            sys.exit(EXIT_ERROR)
        results, ok, truncated, outside = shodan_lookup(args.api_key, args.net, args.authorized)
        if not ok:
            sys.exit(EXIT_ERROR)
        logger.info(f"[+] Found {len(results)} matching hosts on Shodan within {args.net} "
                    f"(lookup only; nothing was probed).")
        for r in results:
            print(f"  {r['ip']}:{r['port']} ({r['controller']}) [{r['org']}]")
        if args.output:
            export_results(results, args.output)
        if outside:
            logger.error(f"[-] Shodan returned {outside} result(s) outside {args.net}. They were discarded and are "
                         f"not shown or saved; treat this lookup as unreliable.")
        if truncated:
            logger.error("[-] Shodan reported more matches than this result page holds; the list above is incomplete.")
        sys.exit(EXIT_ERROR if (outside or truncated) else EXIT_OK)



if __name__ == "__main__":
    main()
