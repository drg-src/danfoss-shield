import importlib.util, io, json, os, socket, subprocess, sys, tempfile, threading, types, contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "danfoss_shield.py"
TMP = Path(tempfile.mkdtemp(prefix="ds_test_"))
os.environ["NO_COLOR"] = "1"
REAL_RUN = subprocess.run

import gc, warnings
LEAKS = []
_orig_showwarning = warnings.showwarning
def _record_leaks(message, category, filename, lineno, file=None, line=None):
    if issubclass(category, ResourceWarning):
        LEAKS.append(f"{Path(filename).name}:{lineno}: {message}")
    else:
        _orig_showwarning(message, category, filename, lineno, file, line)
warnings.showwarning = _record_leaks
warnings.simplefilter("always", ResourceWarning)

spec = importlib.util.spec_from_file_location("ds", SRC)
ds = importlib.util.module_from_spec(spec); spec.loader.exec_module(ds)

ds.data_dir = lambda: TMP / "data"
ds.config_dir = lambda: TMP / "cfg"
ds.config_file = lambda: TMP / "cfg" / "config"
ds.log_file = lambda: TMP / "data" / "danfoss-shield.log"
ds.is_root = lambda: False

ORIG = {name: getattr(ds, name) for name in (
    "validate_wan_interface", "_run", "default_gateways", "host_forwards", "apply_firewall_rules",
    "scan_targets", "resolve_target", "resolve_wan", "auto_detect_wan_interface", "detect_firewall_backend",
    "rollback_all", "_safe_write_text", "_connect", "PROBE_DEADLINE_MIN", "PORTS", "SSL_PORTS", "ipv6_enabled")}
ds.ipv6_enabled = lambda: True

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  :: {detail}" if detail and not cond else ""))

def make_server(banner: bool, auth_code: int):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                self.send_response(200); self.end_headers()
                self.wfile.write(b"<html>Danfoss StoreView AK-SM</html>" if banner else b"<html>nginx default</html>")
            else:
                self.send_response(auth_code)
                if auth_code in (301, 302): self.send_header("Location", "/login")
                self.end_headers(); self.wfile.write(b"x")
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def make_reset_server():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(16)
    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]

def run_main(argv, patches=None):
    old_argv = sys.argv
    saved = {}
    out = io.StringIO()
    code = 0
    try:
        for k, v in (patches or {}).items():
            saved[k] = getattr(ds, k); setattr(ds, k, v)
        sys.argv = ["danfoss_shield.py"] + list(argv)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                ds.main()
            except SystemExit as e:
                code = 0 if e.code is None else e.code
    finally:
        sys.argv = old_argv
        for k, v in saved.items():
            setattr(ds, k, v)
    return code, out.getvalue()

print("Key redaction")
check("redact_argv masks --api-key VALUE", ds.redact_argv(["x","shodan","--api-key","SECRET123"]).find("SECRET123") == -1
      and "***" in ds.redact_argv(["x","shodan","--api-key","SECRET123"]))
check("redact_argv masks --api-key=VALUE", "SECRET9" not in ds.redact_argv(["--api-key=SECRET9"]))
old_argv = sys.argv
sys.argv = ["danfoss_shield.py","shodan","--api-key","TOPSECRETKEY"]
ds.setup_logging(verbose=True, quiet=False, no_color=True)
for h in list(ds.logger.handlers):
    h.flush()
logtext = ds.log_file().read_text(encoding="utf-8") if ds.log_file().exists() else ""
check("log file does not contain the key", "TOPSECRETKEY" not in logtext, f"log={logtext[-200:]}")
check("log file recorded a redacted audit line", "***" in logtext)
sys.argv = old_argv

print("CIDR cap")
try:
    ds.resolve_target("10.0.0.0/8", ds.MAX_SCAN_HOSTS); check("refuse /8", False, "no raise")
except ValueError: check("refuse /8", True)
try:
    ds.resolve_target("2001:db8::/64", ds.MAX_SCAN_HOSTS); check("refuse IPv6 /64", False, "no raise")
except ValueError: check("refuse IPv6 /64", True)
ips, ok = ds.resolve_target("192.168.1.0/30", ds.MAX_SCAN_HOSTS)
check("accept small /30", ok and len(ips) == 2, f"ips={ips}")

print("Honest scan states")
s_open, p_open = make_server(True, 200)
s_unk, p_unk = make_server(True, 302)
s_clo, p_clo = make_server(True, 403)
s_non, p_non = make_server(False, 404)
orig_ports = ds.PORTS
ds.PORTS = [p_open]; check("200 -> open", ds.scan_host("127.0.0.1",2.0,0)["auth"] == ds.AUTH_OPEN)
ds.PORTS = [p_unk]; check("302 -> unknown", ds.scan_host("127.0.0.1",2.0,0)["auth"] == ds.AUTH_UNKNOWN)
ds.PORTS = [p_clo]; check("403 -> closed", ds.scan_host("127.0.0.1",2.0,0)["auth"] == ds.AUTH_CLOSED)
ds.PORTS = [p_non]; check("no banner -> None", ds.scan_host("127.0.0.1",2.0,0) is None)
deadp = free_port()
ds.PORTS = [deadp, p_open]
r = ds.scan_host("127.0.0.1", 2.0, 0)
check("controller on 2nd port still found", r is not None and r["auth"] == ds.AUTH_OPEN)
s_err, p_err = make_reset_server()
ds.PORTS = [p_err]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("all-ports-error -> probe_error unknown", r is not None and r.get("probe_error") and r["auth"] == ds.AUTH_UNKNOWN)
ds.PORTS = orig_ports

env = dict(os.environ, NO_COLOR="1", USERPROFILE=str(TMP), HOME=str(TMP))
rc_err, _o = run_main(["scan","127.0.0.1","--rate-limit","0","--timeout","1","-w","4"], {"PORTS": [p_err]})
check("scan of a host whose port errors exits 1", rc_err == 1, f"rc={rc_err}")

print("Rollback both backends")
def fake_run_factory(state):
    def fake_run(cmd, **kw):
        c = cmd if isinstance(cmd, list) else [cmd]
        joined = " ".join(c)
        rc = 0; out = ""
        if c[0] in ("nft","iptables","ip6tables") and "--version" in c:
            rc = 0 if ((c[0]=="nft" and state["nft"]) or (c[0] in ("iptables","ip6tables") and state["ipt"])) else 1
        elif c[:3] == ["nft","list","tables"]:
            out = "table inet danfoss_shield\n" if state["nft_table"] else "table ip filter\n"
        elif c[:3] == ["nft","list","table"]:
            rc = 0 if state["nft_table"] else 1
        elif c[:3] == ["nft","delete","table"]:
            rc = 0 if state["nft_delete_ok"] else 1
            if rc == 0: state["nft_table"] = False
        elif c[0] in ("iptables","ip6tables") and c[1] == "-S":
            chain = c[2]
            if c[0]=="iptables" and chain=="FORWARD" and state["ipt_fwd_rule"]:
                out = '-A FORWARD -i eth0 -d 192.168.1.5 -m comment --comment danfoss_shield -j DROP\n'
            else:
                out = ""
        elif c[0] in ("iptables","ip6tables") and c[1] == "-D":
            rc = 0 if state["ipt_delete_ok"] else 1
        state["log"].append(joined)
        return subprocess.CompletedProcess(c, rc, out, "")
    return fake_run

ds.is_root = lambda: True
st = {"nft":True,"ipt":True,"nft_table":False,"nft_delete_ok":True,"ipt_fwd_rule":True,
      "ipt_delete_ok":True,"log":[]}
ds.subprocess.run = fake_run_factory(st)
summ = ds.rollback_all(dry_run=False)
removed_ipt = any(x.startswith("iptables -D FORWARD") for x in st["log"])
check("cross-backend: iptables rule removed even though nft exists", removed_ipt and summ["removed"] >= 1, f"log={st['log']}")
check("cross-backend: no false failure", summ["failed"] == 0, f"summ={summ}")

st2 = {"nft":True,"ipt":False,"nft_table":True,"nft_delete_ok":False,"ipt_fwd_rule":False,
       "ipt_delete_ok":True,"log":[]}
ds.subprocess.run = fake_run_factory(st2)
summ2 = ds.rollback_all(dry_run=False)
check("nft delete failure counted as failed", summ2["failed"] >= 1, f"summ2={summ2}")
import subprocess as _sp; ds.subprocess.run = REAL_RUN
ds.is_root = lambda: False

print("Systemd scan command")
argv = ds._exec_start("192.168.1.0/24", TMP/"scans")
ok_new, err_new = ds._parse_check(argv[2:])
check("generated command (--quiet before scan) parses", ok_new, err_new)
ok_old, _ = ds._parse_check(["scan","192.168.1.0/24","--quiet","--output","x.json"])
check("old order (scan ... --quiet) is rejected", not ok_old)

print("Systemd config validation")
sdhome = TMP / "sdhome"
sdhome.mkdir(parents=True, exist_ok=True)
os.environ["USERPROFILE"] = str(sdhome); os.environ["HOME"] = str(sdhome)
try:
    ds.install_systemd_timer("1.2.3.0/24\n[Service]\nExecStart=/evil")
    check("malicious multiline subnet refused", False, "no SystemExit")
except SystemExit as e:
    check("malicious multiline subnet refused", (e.code or 0) != 0, f"code={e.code}")
try:
    ds.install_systemd_timer("192.168.1.0/24"); wrote = True
except SystemExit as e:
    wrote = False; print("   unexpected SystemExit", e.code)
svc = list(sdhome.rglob("danfoss-shield.service"))
unit_txt = svc[0].read_text() if svc else ""
check("valid subnet writes a service unit", wrote and bool(svc))
check("ExecStart has --quiet before scan", "--quiet scan" in unit_txt.replace("  ", " "), unit_txt[:200])

print("CSV sanitisation")
out_csv = TMP/"out.csv"
ds.export_results([{"ip":"1.2.3.4","port":80,"controller":"=cmd|' /C calc'!A1","auth":"open","org":"+SUM(1)"}], str(out_csv))
csv_txt = out_csv.read_text()
check("leading = neutralised", "'=cmd" in csv_txt, csv_txt)
check("leading + neutralised", "'+SUM" in csv_txt, csv_txt)

print("Fix target guards")
try:
    ds.require_authorized(["8.8.8.8"], False); check("require_authorized refuses public w/o flag", False)
except ValueError: check("require_authorized refuses public w/o flag", True)
ds.require_authorized(["192.168.1.9"], False); check("require_authorized allows private", True)
ds.default_gateways = lambda: ([], True)
ds.host_forwards = lambda v6: True
ds.validate_wan_interface = lambda w: None
try:
    ds.apply_firewall_rules(["8.8.8.8"], "eth0", "nftables", dry_run=True, force=False, backup=False)
    check("apply refuses public fix target", False)
except ValueError as e:
    check("apply refuses public fix target", "INTERNAL" in str(e))
cap = {"cmds":[]}
def cap_run(cmd, dry_run, quiet_fail=False):
    cap["cmds"].append(" ".join(cmd)); return True
ds._run = cap_run
summ = ds.apply_firewall_rules(["192.168.1.50"], "eth0", "nftables", dry_run=True, force=False, backup=False)
check("private target builds FORWARD rule", any("forward" in c and "192.168.1.50" in c for c in cap["cmds"]) and summ["applied"]==1,
      f"cmds={cap['cmds']}")

print("File permissions")
if os.name == "posix":
    mode = oct(os.stat(ds.data_dir()).st_mode & 0o777)
    check("data dir is 0700", mode == "0o700", mode)
    lm = oct(os.stat(ds.log_file()).st_mode & 0o777)
    check("log file is 0600", lm == "0o600", lm)
else:
    check("perms are POSIX-only (skipped on Windows)", True, "SKIP")


print("--api abbreviation")
check("redact masks --api VALUE (abbrev)", "SX1" not in ds.redact_argv(["shodan","--api","SX1"]) and "***" in ds.redact_argv(["shodan","--api","SX1"]))
check("redact masks --api=VALUE (abbrev)", "SX2" not in ds.redact_argv(["--api=SX2"]))
check("redact masks --api-k VALUE (abbrev)", "SX3" not in ds.redact_argv(["--api-k","SX3"]))
_abbr_parser = ds.build_parser(ds.load_config())[-1]
_abbr_rej = _abbr_eq_rej = False
try:
    with contextlib.redirect_stderr(io.StringIO()):
        _abbr_parser.parse_args(["shodan", "--api", "LEAKME"])
except SystemExit:
    _abbr_rej = True
try:
    with contextlib.redirect_stderr(io.StringIO()):
        _abbr_parser.parse_args(["shodan", "--api=LEAKME"])
except SystemExit:
    _abbr_eq_rej = True
check("`shodan --api X` rejected by parser (allow_abbrev=False)", _abbr_rej)
check("`shodan --api=X` rejected by parser", _abbr_eq_rej)
_ns = _abbr_parser.parse_args(["shodan", "--api-key", "REALKEY", "--net", "8.8.8.0/28"])
check("`shodan --api-key X` still accepted", _ns.api_key == "REALKEY")

print("Closed+errored -> unknown")
ds.PORTS = [p_clo, p_err]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("closed finding + errored port -> unknown", r is not None and r["auth"] == ds.AUTH_UNKNOWN and r.get("partial_probe"), f"r={r}")
ds.PORTS = [p_open, p_err]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("open finding NOT downgraded by errored port", r is not None and r["auth"] == ds.AUTH_OPEN)
ds.PORTS = orig_ports

print("Fingerprints")
check("generic Emerson/Copeland dropped", b"Emerson" not in ds.DIXELL_FINGERPRINTS and b"Copeland" not in ds.DIXELL_FINGERPRINTS and b"Dixell" in ds.DIXELL_FINGERPRINTS)

print("200 html heuristic")
def _html_auth_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                self.send_response(200); self.end_headers(); self.wfile.write(b"<html>Danfoss StoreView</html>")
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"<!DOCTYPE html><html>login</html>")
        def log_message(self,*a): pass
    srv = HTTPServer(("127.0.0.1",0),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
    return srv.server_address[1]
p_html = _html_auth_server()
check("200 html page -> unknown (no false open)", ds.check_auth_endpoint("127.0.0.1", p_html, "Danfoss StoreView", 2.0, 0) == ds.AUTH_UNKNOWN)
def _body_auth_server(auth_body):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<html>Danfoss StoreView</html>" if self.path == "/" else auth_body)
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]
p_empty = _body_auth_server(b"")
check("200 with an empty body -> unknown (no false open)",
      ds.check_auth_endpoint("127.0.0.1", p_empty, "Danfoss StoreView", 2.0, 0) == ds.AUTH_UNKNOWN)
check("200 with a whitespace-only body -> unknown",
      ds.check_auth_endpoint("127.0.0.1", _body_auth_server(b" \r\n\t "), "Danfoss StoreView", 2.0, 0) == ds.AUTH_UNKNOWN)
check("200 with a data body is still open",
      ds.check_auth_endpoint("127.0.0.1", _body_auth_server(b"  <?xml version=\"1.0\"?><auth/>"), "Danfoss StoreView", 2.0, 0) == ds.AUTH_OPEN)
_saved_ports = ds.PORTS; ds.PORTS = [p_empty]
_r_empty = ds.scan_host("127.0.0.1", 2.0, 0)
ds.PORTS = _saved_ports
check("a controller whose auth endpoint answers an empty 200 is reported unknown, not open",
      _r_empty is not None and _r_empty["controller"] == "Danfoss StoreView" and _r_empty["auth"] == ds.AUTH_UNKNOWN, f"{_r_empty}")

print(">4KB fingerprint")
def _big_banner_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<html>" + b" "*5000 + b"Danfoss StoreView</html>")
        def log_message(self,*a): pass
    srv = HTTPServer(("127.0.0.1",0),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
    return srv.server_address[1]
p_big = _big_banner_server()
_body, _ctype, _err = ds.http_probe("127.0.0.1", p_big, 2.0, 0)
check("controller identified past 4 KB", _ctype == "Danfoss StoreView" and not _err, f"ctype={_ctype}")

print("Txt sanitisation")
out_txt = TMP/"out.txt"
ds.export_results([{"ip":"=HYPERLINK(1)","port":80,"controller":"Danfoss","auth":"open"}], str(out_txt))
check("txt sink neutralises leading =", "'=HYPERLINK" in out_txt.read_text())

print("Rollback guards")
try:
    ds.rollback_all(dry_run=False); check("rollback without root raises", False)
except PermissionError: check("rollback without root raises", True)
ds.is_root = lambda: True
def _no_tools_run(cmd, **kw):
    c = cmd if isinstance(cmd, list) else [cmd]
    if c and c[-1] == "--version": return subprocess.CompletedProcess(c, 1, "", "")
    return subprocess.CompletedProcess(c, 0, "", "")
ds.subprocess.run = _no_tools_run
summ_nb = ds.rollback_all(dry_run=False)
check("no backend -> backends count 0", summ_nb.get("backends", -1) == 0, f"summ={summ_nb}")
ds.subprocess.run = REAL_RUN
ds.is_root = lambda: False

print("Ip6tables-save in snapshot")
_saved = []
def _cap_save_run(cmd, **kw):
    c = cmd if isinstance(cmd, list) else [cmd]
    _saved.append(c[0]); return subprocess.CompletedProcess(c, 0, "rules\n", "")
ds.subprocess.run = _cap_save_run
ds.save_applied_rules("iptables")
ds.subprocess.run = REAL_RUN
check("save_applied_rules runs ip6tables-save too", "ip6tables-save" in _saved and "iptables-save" in _saved, f"calls={_saved}")

print("Shodan error-json")
class _FakeResp:
    def __init__(self, data): self._d = data.encode()
    def read(self, n=-1): return self._d
    def __enter__(self): return self
    def __exit__(self, *a): return False
_orig_urlopen = ds.urllib.request.urlopen
ds.urllib.request.urlopen = lambda req, timeout=10: _FakeResp('{"error":"bad key"}')
_r_l3, _ok_l3 = ds.query_shodan("KEY", "q")
check("shodan error-JSON -> failure (not empty-ok)", _r_l3 is None and _ok_l3 is False, f"ok={_ok_l3}")
ds.urllib.request.urlopen = lambda req, timeout=10: _FakeResp('{"matches": [], "total": 0}')
_r_ok, _ok_ok = ds.query_shodan("KEY", "q")
check("shodan 0-matches -> empty but OK", _r_ok == [] and _ok_ok is True, f"r={_r_ok} ok={_ok_ok}")
ds.urllib.request.urlopen = _orig_urlopen

print("Logging degrades when data dir is uncreatable")
_od, _olf = ds.data_dir, ds.log_file
_afile = TMP / "afile"; _afile.write_text("x")
ds.data_dir = lambda: _afile / "data"
ds.log_file = lambda: _afile / "data" / "danfoss-shield.log"
_crashed = False
try:
    _lg = ds.setup_logging(verbose=False, quiet=False, no_color=True)
except Exception:
    _crashed = True; _lg = None
check("setup_logging survives an uncreatable data dir (no crash)", _crashed is False)
check("falls back to console-only (no FileHandler)",
      _lg is not None
      and any(isinstance(h, ds.logging.StreamHandler) and not isinstance(h, ds.logging.FileHandler) for h in _lg.handlers)
      and not any(isinstance(h, ds.logging.FileHandler) for h in _lg.handlers))
ds.data_dir, ds.log_file = _od, _olf
ds.setup_logging(verbose=False, quiet=False, no_color=True)

for _name, _val in ORIG.items():
    setattr(ds, _name, _val)

print("Connections are closed on error")
class _FakeConn:
    sock = None
    def __init__(self): self.closed = False
    def connect(self): pass
    def request(self, *a, **k): pass
    def getresponse(self): raise OSError("boom")
    def close(self): self.closed = True
_fc = _FakeConn()
ds._connect = lambda h, p, t: _fc
_b, _c, _e = ds.http_probe("192.0.2.1", 80, 1.0, 0)
check("http_probe closes the connection when getresponse raises", _fc.closed and _e is True and _b is None)
_fc2 = _FakeConn()
ds._connect = lambda h, p, t: _fc2
check("check_auth_endpoint closes the connection when getresponse raises",
      ds.check_auth_endpoint("192.0.2.1", 80, "Danfoss StoreView", 1.0, 0) == ds.AUTH_UNKNOWN and _fc2.closed)
ds._connect = ORIG["_connect"]

print("Rate limiter sleeps outside the lock, on a monotonic clock")
class _FakeTime:
    def __init__(self): self.now = 100.0; self.sleeps = []
    def monotonic(self): return self.now
    def time(self): raise AssertionError("wall clock must not be used by the rate limiter")
    def sleep(self, s): raise AssertionError("the rate limiter must wait on the stop event, not sleep")
_ft = _FakeTime()
class _FakeStop:
    def wait(self, s): _ft.sleeps.append((round(s, 6), ds.rate_limit_lock.locked())); _ft.now += s; return False
    def is_set(self): return False
    def set(self): pass
    def clear(self): pass
_real_time, _real_stop = ds.time, ds.stop_scan
ds.time = _ft
ds.stop_scan = _FakeStop()
ds.next_request_slot = 0.0
try:
    ds.enforce_rate_limit(10.0); ds.enforce_rate_limit(10.0); ds.enforce_rate_limit(10.0)
    ds.enforce_rate_limit(0)
finally:
    ds.time = _real_time
    ds.stop_scan = _real_stop
    ds.next_request_slot = 0.0
check("rate limiter: first call free, next two wait one interval each",
      [s for s, _l in _ft.sleeps] == [0.1, 0.1], f"sleeps={_ft.sleeps}")
check("rate limiter: lock is not held while sleeping", all(not locked for _s, locked in _ft.sleeps), f"sleeps={_ft.sleeps}")

print("WAN interface name validation")
_real_listdir = os.listdir
def _fake_listdir(path="."):
    if str(path) == "/sys/class/net":
        return ["lo", "eth0", "eth0.10", "odd;name", "a" * 16]
    return _real_listdir(path)
os.listdir = _fake_listdir
try:
    _bad = ["../x", "/etc", "eth0;flush ruleset", "eth0 ", "eth0\n", "", ".", "..", "a" * 16, "wlan0", "eth0/../lo", None]
    _raised = []
    for _w in _bad:
        try:
            ds.validate_wan_interface(_w); _raised.append(False)
        except ValueError:
            _raised.append(True)
    check("validate_wan_interface refuses traversal, separators, unknown and oversize names", all(_raised),
          f"accepted={[w for w, r in zip(_bad, _raised) if not r]}")
    _ok_names = True
    try:
        ds.validate_wan_interface("eth0"); ds.validate_wan_interface("eth0.10")
    except ValueError:
        _ok_names = False
    check("validate_wan_interface accepts a listed interface", _ok_names)
    _odd = []
    for _w in ("odd;name", "a" * 16):
        try:
            ds.validate_wan_interface(_w); _odd.append(False)
        except ValueError:
            _odd.append(True)
    check("an existing interface with an unsafe or oversize name is still refused", all(_odd), f"refused={_odd}")
finally:
    os.listdir = _real_listdir

print("IPv4-mapped addresses")
check("mapped public address is not local", ds.is_local_address("::ffff:8.8.8.8") is False)
check("mapped private address is local", ds.is_local_address("::ffff:192.168.1.5") is True)
try:
    ds.require_authorized(["::ffff:8.8.8.8"], False); check("require_authorized refuses a mapped public address", False)
except ValueError:
    check("require_authorized refuses a mapped public address", True)
_applied = []
def _rec_apply(ips, wan, backend, dry_run, force, backup, routed=False):
    _applied.append(list(ips)); return {"applied": len(ips), "existing": 0, "skipped": 0}
_fixp = {"apply_firewall_rules": _rec_apply, "resolve_wan": lambda e, c: "eth0", "detect_firewall_backend": lambda p: "nftables"}
_rc, _out = run_main(["fix", "::ffff:192.168.1.5", "--dry-run"], _fixp)
check("fix refuses an IPv4-mapped target (exit 1, nothing applied)", _rc == 1 and not _applied and "IPv4-mapped" in _out, f"rc={_rc}")

print("CSV leading line feed")
check("csv_safe neutralises a leading line feed", ds.csv_safe("\n=cmd").startswith("'"))

print("Usage errors exit 1, not 2")
_rc, _o = run_main(["scan", "--bogus-flag"])
check("unknown flag exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["nosuchcommand"])
check("unknown subcommand exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["fix"], _fixp)
check("fix with no targets exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["--version"])
check("--version exits 0", _rc == 0, f"rc={_rc}")
_sub = subprocess.run([sys.executable, "-I", str(SRC), "scan", "--bogus-flag"], capture_output=True, text=True, env=env)
check("real process: usage error exits 1", _sub.returncode == 1, f"rc={_sub.returncode}")

print("A refused port is a closed port, not a probe error")
_refused = free_port()
_REF_T = 5.0
_b, _c, _e = ds.http_probe("127.0.0.1", _refused, _REF_T, 0)
check("http_probe: refused -> not errored, no body", _b is None and _c == "" and _e is False)
_b, _c, _e = ds.http_probe("127.0.0.1", p_err, 2.0, 0)
check("http_probe: reset connection -> errored", _e is True)
ds.PORTS = [_refused]
check("scan_host: all ports refused -> None (no controller, no error)", ds.scan_host("127.0.0.1", _REF_T, 0) is None)
ds.PORTS = [p_clo, _refused]
r = ds.scan_host("127.0.0.1", _REF_T, 0)
check("closed finding + refused port stays closed", r is not None and r["auth"] == ds.AUTH_CLOSED and not r.get("partial_probe"), f"r={r}")
ds.PORTS = ORIG["PORTS"]
_rc, _o = run_main(["scan", "127.0.0.1", "--rate-limit", "0", "--timeout", "5", "-w", "2"], {"PORTS": [_refused]})
check("scan of a host with only refused ports exits 0", _rc == 0, f"rc={_rc}")

print("Fix exit codes")
def _scan_stub(found, probe_errors=0, unresolved=()):
    def stub(targets, workers, timeout, rate_limit, max_hosts, authorized=False):
        return list(found), {"unresolved": list(unresolved), "total": 3, "probe_errors": probe_errors}
    return stub
_applied.clear()
_rc, _o = run_main(["fix", "--all", "192.168.1.0/30", "--dry-run"], dict(_fixp, scan_targets=_scan_stub([], probe_errors=3)))
check("fix --all: scan failed and nothing found -> exit 1, nothing applied", _rc == 1 and not _applied and "Nothing was blocked" in _o, f"rc={_rc}")
_rc, _o = run_main(["fix", "--all", "192.168.1.0/30", "--dry-run"], dict(_fixp, scan_targets=_scan_stub([], unresolved=["nope.invalid"])))
check("fix --all: unresolved name and nothing found -> exit 1", _rc == 1 and not _applied, f"rc={_rc}")
_rc, _o = run_main(["fix", "--all", "192.168.1.0/30", "--dry-run"], dict(_fixp, scan_targets=_scan_stub([])))
check("fix --all: clean scan, nothing found -> exit 0", _rc == 0 and not _applied, f"rc={_rc}")
_found = [{"ip": "192.168.1.5", "port": 80, "controller": "Danfoss StoreView", "match": "StoreView", "auth": "open"}]
_rc, _o = run_main(["fix", "--all", "192.168.1.0/30", "--dry-run"], dict(_fixp, scan_targets=_scan_stub(_found)))
check("fix --all: clean scan, controller blocked -> exit 0", _rc == 0 and _applied == [["192.168.1.5"]], f"rc={_rc} applied={_applied}")
check("fix --all prints the matched fingerprint", "matched 'StoreView'" in _o)
check("fix summary discloses that open sessions survive", "already open" in _o and "IPv4 1, IPv6 0" in _o)
check("fix --all summary discloses the IPv4-only sweep", "does not find IPv6" in _o)
_applied.clear()
_rc, _o = run_main(["fix", "--all", "192.168.1.0/30", "--dry-run"], dict(_fixp, scan_targets=_scan_stub(_found, probe_errors=2)))
check("fix --all: controller blocked but scan partial -> exit 1", _rc == 1 and _applied == [["192.168.1.5"]], f"rc={_rc}")
def _resolve_stub(table):
    def stub(target, max_hosts):
        return table.get(target, ([], False))
    return stub
_applied.clear()
_rc, _o = run_main(["fix", "nope.invalid", "--dry-run"], dict(_fixp, resolve_target=_resolve_stub({})))
check("fix <name>: name does not resolve -> exit 1, nothing applied", _rc == 1 and not _applied, f"rc={_rc}")
_rc, _o = run_main(["fix", "good.lan", "nope.invalid", "--dry-run"],
                   dict(_fixp, resolve_target=_resolve_stub({"good.lan": (["192.168.1.5"], True)})))
check("fix <names>: one resolves, one does not -> the good one applied, exit 1",
      _rc == 1 and _applied == [["192.168.1.5"]] and "NOT blocked" in _o, f"rc={_rc} applied={_applied}")
_applied.clear()
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run"], _fixp)
check("fix <ip>: applied -> exit 0", _rc == 0 and _applied == [["192.168.1.5"]], f"rc={_rc}")

print("Fingerprint match is recorded")
ds.PORTS = [p_open]
r = ds.scan_host("127.0.0.1", 2.0, 0)
check("scan result carries the matched fingerprint", r is not None and r.get("match") == "StoreView", f"r={r}")
ds.PORTS = ORIG["PORTS"]
check("identify_controller names the generic match", ds.identify_controller(b"x System Manager y") == ("Danfoss StoreView", "System Manager"))
check("identify_controller: no match", ds.identify_controller(b"<html>nginx</html>") == ("", ""))

print("WAN auto-detection refuses to guess")
def _route_run(v4, v6, raise_exc=None, rc=0):
    def fake(cmd, **kw):
        if raise_exc is not None:
            raise raise_exc
        if rc and kw.get("check"):
            raise subprocess.CalledProcessError(rc, cmd, "", "boom")
        return subprocess.CompletedProcess(cmd, rc, v6 if "-6" in cmd else v4, "")
    return fake
def _detect(v4, v6, **kw):
    ds.subprocess.run = _route_run(v4, v6, **kw)
    try:
        return ds.auto_detect_wan_interface()
    except ValueError as e:
        return e
    finally:
        ds.subprocess.run = REAL_RUN
check("one default-route interface is used", _detect("default via 192.168.1.1 dev eth0 proto dhcp\n", "") == "eth0")
check("same interface for IPv4 and IPv6 is used", _detect("default via 192.168.1.1 dev eth0\n", "default via fe80::1 dev eth0 metric 1024\n") == "eth0")
check("two IPv4 default routes -> refused", isinstance(_detect("default via 10.0.0.1 dev eth0\ndefault via 10.1.0.1 dev eth1\n", ""), ValueError))
check("IPv6 uplink on another interface -> refused", isinstance(_detect("default via 10.0.0.1 dev eth0\n", "default via fe80::1 dev tun0\n"), ValueError))
check("no default route -> refused (no first-interface or eth0 guess)", isinstance(_detect("", ""), ValueError))
check("ip tool missing -> refused", isinstance(_detect("", "", raise_exc=FileNotFoundError("ip")), ValueError))
check("ip tool failing -> refused", isinstance(_detect("", "", rc=1), ValueError))
def _raise_detect():
    raise ValueError("WAN interface not auto-detected")
_applied.clear()
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run"],
                   {"apply_firewall_rules": _rec_apply, "detect_firewall_backend": lambda p: "nftables",
                    "auto_detect_wan_interface": _raise_detect})
check("fix without --wan and no safe auto-detect -> exit 1, nothing applied", _rc == 1 and not _applied, f"rc={_rc}")
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run", "--wan", "eth7"],
                   {"apply_firewall_rules": _rec_apply, "detect_firewall_backend": lambda p: "nftables",
                    "auto_detect_wan_interface": _raise_detect})
check("explicit --wan skips auto-detection", _rc == 0 and _applied == [["192.168.1.5"]], f"rc={_rc}")
_rc, _o = run_main(["fix", "--rollback", "--dry-run"],
                   {"rollback_all": lambda dry: {"removed": 1, "failed": 0, "backends": 1, "saved_files": []},
                    "auto_detect_wan_interface": _raise_detect})
check("rollback does not need a WAN interface", _rc == 0, f"rc={_rc}")

print("Rollback counts what it could not check")
def _rb_run(state):
    def fake(cmd, **kw):
        c = list(cmd)
        out = ""; rc = 0
        if c[-1] == "--version":
            if c[0] == "nft" and not state.get("nft", True): rc = 1
            if c[0] == "iptables" and not state.get("ipt", True): rc = 1
        elif c[:3] == ["nft", "list", "tables"]:
            rc = 1 if state.get("nft_list_fail") else 0
            out = state.get("nft_tables", "")
        elif c[0] in ("iptables", "ip6tables") and c[1] == "-S":
            if c[0] == "ip6tables" and state.get("ip6_missing"):
                raise FileNotFoundError("ip6tables")
            if state.get("ipt_list_fail"):
                rc = 1
        state.setdefault("log", []).append(" ".join(c))
        if rc and kw.get("check"):
            raise subprocess.CalledProcessError(rc, c, out, "permission denied")
        return subprocess.CompletedProcess(c, rc, out, "")
    return fake
ds.is_root = lambda: True
def _rollback(state):
    ds.subprocess.run = _rb_run(state)
    try:
        return ds.rollback_all(dry_run=False)
    finally:
        ds.subprocess.run = REAL_RUN
_s = _rollback({"ipt_list_fail": True})
check("iptables -S failure is counted as failed", _s["failed"] >= 1, f"summ={_s}")
_s = _rollback({"nft_list_fail": True})
check("nft list tables failure is counted as failed", _s["failed"] >= 1, f"summ={_s}")
_s = _rollback({"ip6_missing": True})
check("missing ip6tables is skipped, not a failure", _s["failed"] == 0, f"summ={_s}")
_st = {"nft_tables": "table ip filter\ntable inet danfoss_shield\n"}
_s = _rollback(_st)
check("nft table present -> deleted", _s["removed"] == 1 and any(x.startswith("nft delete table") for x in _st["log"]), f"summ={_s}")
_st = {"nft_tables": "table inet danfoss_shield2\ntable ip danfoss_shield\n"}
_s = _rollback(_st)
check("look-alike nft table names are not deleted", _s["removed"] == 0 and not any(x.startswith("nft delete") for x in _st["log"]), f"log={_st['log']}")
(TMP / "data").mkdir(parents=True, exist_ok=True)
_savedf = TMP / "data" / "danfoss_shield.nft"
_savedf.write_text("table inet danfoss_shield {}\n")
_s = _rollback({})
check("rollback keeps the saved rule file and reports it", _savedf.exists() and str(_savedf) in _s.get("saved_files", []), f"summ={_s}")
_savedf.unlink()
ds.is_root = lambda: False
_rc, _o = run_main(["fix", "--rollback"], {"rollback_all": lambda dry: {"removed": 0, "failed": 1, "backends": 1, "saved_files": []}})
check("rollback with a failed check exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["fix", "--rollback"], {"rollback_all": lambda dry: {"removed": 0, "failed": 0, "backends": 1, "saved_files": []}})
check("rollback that found nothing exits 0 and says so", _rc == 0 and "Nothing was removed" in _o, f"rc={_rc}")

print("Per-probe wall-clock deadline")
def _drip_server(mode):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
    stop = threading.Event()
    def serve_one(conn):
        try:
            conn.settimeout(1)
            try:
                conn.recv(4096)
            except OSError:
                pass
            if mode == "body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(400):
                if stop.is_set():
                    break
                conn.sendall(b"x")
                stop.wait(0.1)
        except OSError:
            pass
        finally:
            conn.close()
    def loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve_one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1], stop
import time as _time
ds.PROBE_DEADLINE_MIN = 1.5
for _mode in ("body", "headers"):
    _srv, _port, _stop = _drip_server(_mode)
    _t0 = _time.monotonic()
    _b, _c, _e = ds.http_probe("127.0.0.1", _port, 0.5, 0)
    _dt = _time.monotonic() - _t0
    check(f"slow-drip {_mode}: probe ends at the deadline and counts as errored",
          _e is True and 1.3 <= _dt <= 4.0, f"errored={_e} elapsed={_dt:.2f}s")
    _hit = False
    try:
        ds._fetch("127.0.0.1", _port, "/", 0.5, 65536)
    except ds.ProbeDeadline:
        _hit = True
    except Exception:
        _hit = False
    check(f"slow-drip {_mode}: _fetch raises ProbeDeadline", _hit)
    _stop.set(); _srv.close()
ds.PROBE_DEADLINE_MIN = ORIG["PROBE_DEADLINE_MIN"]
_b, _c, _e = ds.http_probe("127.0.0.1", p_big, 2.0, 0)
check("a normal server is unaffected by the deadline", _c == "Danfoss StoreView" and not _e)

print("Shodan lookup is limited to your own range")
_want_q = "net:8.8.8.0/28 port:80,443,8080,8443,3080,3443"
check("scope query is built from fixed parts", ds.shodan_scope_query("8.8.8.0/28", True) == _want_q)
def _refuses(net, authorized):
    try:
        ds.shodan_scope_query(net, authorized); return False
    except ValueError:
        return True
check("public range without --authorized is refused", _refuses("8.8.8.0/28", False))
check("private range is refused", _refuses("192.168.1.0/24", True))
check("invalid range is refused", _refuses("not-a-net", True) and _refuses('8.8.8.0/28 OR "x"', True))
check("range over the cap is refused", _refuses("8.0.0.0/8", True))
_urls = []
def _shodan_fake(payload):
    def fake(req, timeout=10):
        _urls.append(req.full_url); return _FakeResp(json.dumps(payload))
    return fake
_one = {"matches": [{"ip_str": "8.8.8.5", "port": 80, "data": "HTTP/1.1 200 OK StoreView", "org": "Mine"}], "total": 1}
ds.urllib.request.urlopen = _shodan_fake(_one)
_res, _ok, _trunc, _outside = ds.shodan_lookup("KEY", "8.8.8.0/28", True)
_sent = ds.urllib.parse.parse_qs(ds.urllib.parse.urlsplit(_urls[-1]).query).get("query", [""])[0]
check("lookup sends exactly the scoped query", _sent == _want_q, f"sent={_sent}")
check("lookup returns the match, complete", _ok and not _trunc and _res and _res[0]["controller"] == "Danfoss StoreView")
_saved_env = os.environ.pop("SHODAN_API_KEY", None)
_rc, _o = run_main(["shodan", "--api-key", "KEY", "--net", "8.8.8.0/28", "--authorized"])
check("shodan lookup success exits 0", _rc == 0, f"rc={_rc}")
ds.urllib.request.urlopen = _shodan_fake(dict(_one, total=5))
_res, _ok, _trunc, _outside = ds.shodan_lookup("KEY", "8.8.8.0/28", True)
check("more matches than the page holds -> truncated", _ok and _trunc)
_rc, _o = run_main(["shodan", "--api-key", "KEY", "--net", "8.8.8.0/28", "--authorized"])
check("truncated shodan result exits 1 and says so", _rc == 1 and "incomplete" in _o, f"rc={_rc}")
_n_before = len(_urls)
_rc1, _o = run_main(["shodan", "--api-key", "KEY"])
_rc2, _o = run_main(["shodan", "--api-key", "KEY", "--net", "8.8.8.0/28"])
_rc3, _o = run_main(["shodan", "--api-key", "KEY", "--net", "8.8.8.0/28", "--authorized", "--query", "x"])
_rc4, _o = run_main(["shodan", "--net", "8.8.8.0/28", "--authorized"])
check("shodan without --net exits 1", _rc1 == 1, f"rc={_rc1}")
check("shodan without --authorized exits 1", _rc2 == 1, f"rc={_rc2}")
check("shodan --query is gone (exit 1)", _rc3 == 1, f"rc={_rc3}")
check("shodan without an API key exits 1", _rc4 == 1, f"rc={_rc4}")
check("refused shodan runs send no request", len(_urls) == _n_before, f"extra={len(_urls) - _n_before}")
ds.urllib.request.urlopen = _orig_urlopen
if _saved_env is not None:
    os.environ["SHODAN_API_KEY"] = _saved_env

print("Suricata rules")
_rules_ok = ds.install_suricata_rules()
_rule_path = TMP / "data" / "rules" / ds.SURICATA_RULE_FILE
_rule_txt = _rule_path.read_text() if _rule_path.exists() else ""
check("install returns True and writes the file", _rules_ok is True and bool(_rule_txt))
check("rule messages use the project's own prefix, no borrowed ET prefix, no CVE id",
      "DANFOSS-SHIELD" in _rule_txt and "ET EXPLOIT" not in _rule_txt and "CVE-" not in _rule_txt, _rule_txt[:200])
def _write_fail(path, text):
    raise OSError("disk full")
_rc, _o = run_main(["--install-suricata"], {"_safe_write_text": _write_fail})
check("failed rule write exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["--install-suricata"])
check("rule install exits 0 and warns the rules are not confirmed loaded", _rc == 0 and "NOT confirmed loaded" in _o, f"rc={_rc}")
_rc, _o = run_main(["--remove-suricata"])
check("rule removal exits 0 and removes the file", _rc == 0 and not _rule_path.exists(), f"rc={_rc}")

print("A missing firewall tool is an error, not a traceback")
def _missing_tool(cmd, **kw):
    raise FileNotFoundError(cmd[0])
ds.subprocess.run = _missing_tool
try:
    _started = ds._run(["nft", "add", "table", "inet", "danfoss_shield"], dry_run=False)
    _legacy_crashed = False
    try:
        ds.remove_legacy_input_rules("nftables", dry_run=True)
    except Exception:
        _legacy_crashed = True
finally:
    ds.subprocess.run = REAL_RUN
check("_run returns False when the tool cannot be started", _started is False)
check("the INPUT-chain cleanup survives a missing nft", _legacy_crashed is False)
def _raise_oserror(ips, wan, backend, dry_run, force, backup, routed=False):
    raise OSError("tool vanished")
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run", "--wan", "eth0"],
                   {"apply_firewall_rules": _raise_oserror, "detect_firewall_backend": lambda p: "nftables"})
check("an OS error during fix exits 1 with a message", _rc == 1 and "tool vanished" in _o, f"rc={_rc}")

print("A slow TLS handshake cannot stall a probe")
def _tls_drip_server():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
    stop = threading.Event()
    def serve_one(conn):
        try:
            conn.settimeout(2)
            try:
                conn.recv(4096)
            except OSError:
                pass
            conn.sendall(b"\x16\x03\x03\x40\x00")
            for _ in range(600):
                if stop.is_set():
                    break
                conn.sendall(b"\x00")
                stop.wait(0.1)
        except OSError:
            pass
        finally:
            conn.close()
    def loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve_one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1], stop
_tsrv, _tport, _tstop = _tls_drip_server()
ds.SSL_PORTS = (_tport,)
ds.PROBE_DEADLINE_MIN = 6.0
ds.ssl.create_default_context()
_t0 = _time.monotonic()
_b, _c, _e = ds.http_probe("127.0.0.1", _tport, 0.5, 0)
_dt = _time.monotonic() - _t0
check("slow-drip TLS handshake: the probe ends at the normal timeout (before the deadline) and counts as errored",
      _e is True and _dt < 4.0, f"errored={_e} elapsed={_dt:.2f}s")
_t0 = _time.monotonic()
_raised = None
try:
    ds._fetch("127.0.0.1", _tport, "/", 0.5, 65536)
except Exception as _ex:
    _raised = type(_ex).__name__
_dt2 = _time.monotonic() - _t0
check("slow-drip TLS handshake: _fetch raises a timeout, not the watchdog and not a protocol error",
      _raised in ("TimeoutError", "timeout") and _dt2 < 4.0, f"raised={_raised} elapsed={_dt2:.2f}s")
_tstop.set(); _tsrv.close()
ds.SSL_PORTS = ORIG["SSL_PORTS"]
ds.PROBE_DEADLINE_MIN = ORIG["PROBE_DEADLINE_MIN"]

print("The WAN name is checked inside fix itself")
_ran = []
ds._run = lambda cmd, dry_run, quiet_fail=False: (_ran.append(list(cmd)) or True)
ds.default_gateways = lambda: ([], True)
ds.host_forwards = lambda v6: True
_real_listdir2 = os.listdir
os.listdir = lambda path=".": ["lo", "eth0", "6in4-wan"] if str(path) == "/sys/class/net" else _real_listdir2(path)
try:
    _refused_wan = False
    try:
        ORIG["apply_firewall_rules"](["192.168.1.5"], "eth0;flush ruleset", "nftables", True, False, False)
    except ValueError:
        _refused_wan = True
    check("apply_firewall_rules refuses an unsafe WAN name before any command", _refused_wan and not _ran, f"ran={_ran}")
    _ran.clear()
    _summ = ORIG["apply_firewall_rules"](["192.168.1.5"], "6in4-wan", "nftables", True, False, False)
    _rule = [c for c in _ran if c[:3] == ["nft", "add", "rule"]]
    check("nft rule passes the WAN name quoted", len(_rule) == 1 and '"6in4-wan"' in _rule[0] and _summ["applied"] == 1, f"rule={_rule}")
    _ran.clear()
    ORIG["apply_firewall_rules"](["192.168.1.5"], "eth0", "iptables", True, False, False)
    _ipt = [c for c in _ran if c[:1] == ["iptables"] and "-I" in c]
    check("iptables rule passes the WAN name as its own argument, unquoted", len(_ipt) == 1 and _ipt[0][_ipt[0].index("-i") + 1] == "eth0", f"cmd={_ipt}")
finally:
    os.listdir = _real_listdir2
    for _n in ("_run", "default_gateways", "host_forwards"):
        setattr(ds, _n, ORIG[_n])

print("Default route without a named interface")
check("nexthop-group default (no dev) -> refused, even with an IPv6 default on eth0",
      isinstance(_detect("default nhid 10 proto static\n", "default via fe80::1 dev eth0\n"), ValueError))
check("multipath default with nexthop lines on two devices -> refused",
      isinstance(_detect("default proto static\n\tnexthop via 10.0.0.1 dev eth0 weight 1\n\tnexthop via 10.1.0.1 dev eth1 weight 1\n", ""), ValueError))
check("multipath default with nexthop lines on one device is used",
      _detect("default proto static\n\tnexthop via 10.0.0.1 dev eth0 weight 1\n\tnexthop via 10.0.0.2 dev eth0 weight 1\n", "") == "eth0")

check("a no-interface default beside a separate multipath default is still refused",
      isinstance(_detect("default nhid 10 proto static\ndefault proto static\n\tnexthop via 10.0.0.1 dev eth0 weight 1\n\tnexthop via 10.0.0.2 dev eth0 weight 1\n", ""), ValueError))
check("a blank line in the route output does not crash",
      _detect("\ndefault via 192.168.1.1 dev eth0 proto dhcp metric 100\n\n", "default via fe80::1 dev eth0 proto ra metric 100 pref medium\n") == "eth0")

print("IPv6 detection")
_real_exists, _real_isdir = os.path.exists, os.path.isdir
def _proc(exists_if, isdir_net):
    os.path.exists = lambda p: exists_if if str(p) == "/proc/net/if_inet6" else _real_exists(p)
    os.path.isdir = lambda p: isdir_net if str(p) == "/proc/net" else _real_isdir(p)
    try:
        return ORIG["ipv6_enabled"]()
    finally:
        os.path.exists, os.path.isdir = _real_exists, _real_isdir
check("IPv6 file present -> enabled", _proc(True, True) is True)
check("/proc/net present without the IPv6 file -> disabled", _proc(False, True) is False)
check("/proc not mounted -> treated as enabled (ip6tables is still asked)", _proc(False, False) is True)

print("Rollback on a host with IPv6 off")
ds.is_root = lambda: True
_st6 = {"ip6_fail_only": True}
def _rb6(cmd, **kw):
    c = list(cmd)
    _st6.setdefault("log", []).append(" ".join(c))
    if c[0] == "ip6tables" and c[1] == "-S":
        if kw.get("check"):
            raise subprocess.CalledProcessError(3, c, "", "can't initialize ip6tables table")
        return subprocess.CompletedProcess(c, 3, "", "")
    return subprocess.CompletedProcess(c, 0, "", "")
ds.subprocess.run = _rb6
try:
    ds.ipv6_enabled = lambda: False
    _s_off = ds.rollback_all(dry_run=False)
    _asked6_off = any(x.startswith("ip6tables -S") for x in _st6["log"])
    _st6["log"] = []
    ds.ipv6_enabled = lambda: True
    _s_on = ds.rollback_all(dry_run=False)
finally:
    ds.subprocess.run = REAL_RUN
    ds.ipv6_enabled = lambda: True
    ds.is_root = lambda: False
check("IPv6 off: ip6tables is not asked and rollback reports no failure", _s_off["failed"] == 0 and not _asked6_off, f"summ={_s_off}")
check("IPv6 on: an ip6tables listing failure still counts", _s_on["failed"] >= 1, f"summ={_s_on}")

print("Fixture honours its own state")
ds.is_root = lambda: True
_stf = {"nft": False, "ipt": False, "nft_table": False, "nft_delete_ok": True, "ipt_fwd_rule": False, "ipt_delete_ok": True, "log": []}
ds.subprocess.run = fake_run_factory(_stf)
try:
    _sf = ds.rollback_all(dry_run=False)
finally:
    ds.subprocess.run = REAL_RUN
    ds.is_root = lambda: False
check("no nft and no iptables in the fixture -> backends 0", _sf.get("backends") == 0, f"summ={_sf}")

print("Timer install errors exit 1, no traceback")
_rc, _o = run_main(["--install-timer"], {"_safe_write_text": _write_fail})
check("failed unit write exits 1 with a message", _rc == 1 and "timer was not installed" in _o, f"rc={_rc} out={_o[-200:]}")

print("Suricata rule has no unverified classtype")
ds.install_suricata_rules()
_rt = _rule_path.read_text() if _rule_path.exists() else ""
check("rules carry no classtype keyword", bool(_rt) and "classtype" not in _rt, _rt[:200])
check("rules still carry msg, content, sid and rev", all(k in _rt for k in ('msg:"DANFOSS-SHIELD', 'content:"/xml.cgi?action=getauth"', "sid:9900001", "sid:9900002", "rev:2")))
ds.remove_suricata_rules()

import errno as _errno, shutil as _shutil, ssl as _ssl

def _with_apply_env(fn, gateways=((), True), names=("lo", "eth0"), own=((), True)):
    ran = []
    saved = {n: getattr(ds, n) for n in ("_run", "default_gateways", "host_forwards", "host_addresses")}
    ds.host_addresses = lambda: ([ds.ipaddress.ip_address(a) for a in own[0]], own[1])
    real_ld = os.listdir
    ds._run = lambda cmd, dry_run, quiet_fail=False: (ran.append(list(cmd)) or True)
    ds.default_gateways = lambda: ([ds.ipaddress.ip_address(g) for g in gateways[0]], gateways[1])
    ds.host_forwards = lambda v6: True
    os.listdir = lambda path=".": list(names) if str(path) == "/sys/class/net" else real_ld(path)
    try:
        try:
            return fn(), ran
        except Exception as ex:
            return ex, ran
    finally:
        os.listdir = real_ld
        for n, v in saved.items():
            setattr(ds, n, v)
_real_apply = ORIG["apply_firewall_rules"]

print("--routed accepts a routed public address and nothing else")
_r, _ran = _with_apply_env(lambda: _real_apply(["8.8.8.8"], "eth0", "nftables", True, False, False))
check("public target without --routed is refused, and the message names --routed", isinstance(_r, ValueError) and "--routed" in str(_r) and not _ran)
_r, _ran = _with_apply_env(lambda: _real_apply(["8.8.8.8"], "eth0", "nftables", True, False, False, routed=True))
check("public target with routed=True is applied", isinstance(_r, dict) and _r["applied"] == 1 and any("8.8.8.8" in c for c in _ran), f"r={_r}")
_r, _ran = _with_apply_env(lambda: _real_apply(["8.8.8.8"], "eth0", "nftables", True, False, False, routed=True), gateways=(("8.8.8.8",), True))
check("--routed does not switch off the gateway check", isinstance(_r, ValueError) and "gateway" in str(_r) and not _ran, f"r={_r}")
_r, _ran = _with_apply_env(lambda: _real_apply(["8.8.8.8"], "eth0;x", "nftables", True, False, False, routed=True))
check("--routed does not switch off WAN validation", isinstance(_r, ValueError) and not _ran)
_seen = {}
def _rec_apply_kw(ips, wan, backend, dry_run, force, backup, routed=False):
    _seen["routed"] = routed; _seen["ips"] = list(ips); return {"applied": len(ips), "existing": 0, "skipped": 0}
_rp = {"apply_firewall_rules": _rec_apply_kw, "resolve_wan": lambda e, c: "eth0", "detect_firewall_backend": lambda p: "nftables"}
_rc, _o = run_main(["fix", "8.8.8.8", "--routed", "--dry-run"], _rp)
check("fix --routed on a public address still needs --authorized", _rc == 1 and not _seen, f"rc={_rc}")
_rc, _o = run_main(["fix", "8.8.8.8", "--routed", "--authorized", "--dry-run"], _rp)
check("fix --routed --authorized passes routed through", _rc == 0 and _seen.get("routed") is True and _seen.get("ips") == ["8.8.8.8"], f"rc={_rc} seen={_seen}")

print("Only rules with our exact tag are touched")
def _tag_run(cmd, **kw):
    c = list(cmd)
    out = ""
    if c[0] == "iptables" and c[1] == "-S" and c[2] == "FORWARD":
        out = ("-A FORWARD -i eth0 -d 192.168.1.5 -m comment --comment danfoss_shield -j DROP\n"
               "-A FORWARD -i eth0 -d 192.168.1.6 -m comment --comment danfoss_shield_custom -j DROP\n"
               "-A FORWARD -i eth0 -d 192.168.1.7 -m comment --comment \"my danfoss_shield note\" -j DROP\n")
    elif c[:3] == ["nft", "list", "chain"]:
        out = ('\t\tiifname "eth0" ip daddr 192.168.1.5 ct state new counter packets 0 bytes 0 drop comment "danfoss_shield2"\n'
               '\t\tiifname "eth0" ip daddr 192.168.1.9 ct state new counter packets 0 bytes 0 drop comment "danfoss_shield"\n')
    return subprocess.CompletedProcess(c, 0, out, "")
_deleted = []
ds.subprocess.run = _tag_run
ds._run = lambda cmd, dry_run, quiet_fail=False: (_deleted.append(list(cmd)) or True)
try:
    _removed, _failed = ds.remove_iptables_tagged(["FORWARD"], False)
    _ex_other = ds.check_rule_exists("nftables", "192.168.1.5", "eth0")
    _ex_ours = ds.check_rule_exists("nftables", "192.168.1.9", "eth0")
finally:
    ds.subprocess.run = REAL_RUN
    ds._run = ORIG["_run"]
_del_targets = sorted(c[c.index("-d") + 1] for c in _deleted if c[0] == "iptables")
check("rollback deletes only the rule whose comment is exactly ours", _del_targets == ["192.168.1.5"] and _removed >= 1, f"deleted={_del_targets}")
check("a rule tagged with a look-alike comment does not count as ours (nft)", _ex_other is False and _ex_ours is True)
check("iptables delete waits for the xtables lock", all(c[-2:] == ["-w", "5"] for c in _deleted if c[0] == "iptables"), f"{_deleted}")

print("Iptables commands wait for the lock, in a fixed position")
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5", "fd00::5"], "eth0", "iptables", True, False, False))
_ins = [c for c in _ran if "-I" in c]
check("iptables and ip6tables inserts end with -w 5", len(_ins) == 2 and all(c[-2:] == ["-w", "5"] for c in _ins) and {c[0] for c in _ins} == {"iptables", "ip6tables"}, f"{_ins}")
_listed = []
def _list_run(cmd, **kw):
    _listed.append((list(cmd), kw.get("timeout"))); return subprocess.CompletedProcess(list(cmd), 0, "", "")
ds.subprocess.run = _list_run
try:
    ds.remove_iptables_tagged(["FORWARD"], True); ds.check_rule_exists("iptables", "192.168.1.5", "eth0")
finally:
    ds.subprocess.run = REAL_RUN
check("iptables list and check calls end with -w 5", bool(_listed) and all(c[-2:] == ["-w", "5"] for c, _t in _listed), f"{[c for c, _t in _listed]}")
check("every external command gets the command timeout", bool(_listed) and all(t == ds.CMD_TIMEOUT for _c, t in _listed))

print("A hung external command is a failure, not a hang")
def _hang_run(cmd, **kw):
    raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))
ds.subprocess.run = _hang_run
try:
    _started = ds._run(["nft", "add", "table", "inet", "danfoss_shield"], dry_run=False)
    _state = ds.nft_table_state()
    _gws, _known = ds.default_gateways()
    _det = None
    try:
        ds.auto_detect_wan_interface()
    except ValueError as _ex:
        _det = _ex
    ds.is_root = lambda: True
    try:
        _rb = ds.rollback_all(dry_run=False)
    except Exception as _ex:
        _rb = _ex
finally:
    ds.subprocess.run = REAL_RUN
    ds.is_root = lambda: False
check("_run returns False when the command times out", _started is False)
check("nft_table_state is 'error' when nft hangs", _state == "error")
check("default_gateways reports 'unknown' when ip hangs", _gws == [] and _known is False)
check("auto-detect refuses when ip hangs", isinstance(_det, ValueError))
check("rollback with hanging tools ends as an error or a counted failure, never as success",
      isinstance(_rb, OSError) or (isinstance(_rb, dict) and (_rb["failed"] >= 1 or _rb.get("backends") == 0)), f"rb={_rb}")

print("Gateway self-lockout check")
def _gw_run(v4, v6, fail=False):
    def fake(cmd, **kw):
        if fail:
            raise FileNotFoundError("ip")
        return subprocess.CompletedProcess(list(cmd), 0, v6 if "-6" in cmd else v4, "")
    return fake
ds.subprocess.run = _gw_run("default via 192.168.1.1 dev eth0\ndefault via 192.168.2.1 dev eth1 metric 200\n", "default via fe80::1 dev eth0 proto ra\n")
try:
    _gws, _known = ds.default_gateways()
finally:
    ds.subprocess.run = REAL_RUN
check("all IPv4 and IPv6 default gateways are found", sorted(str(g) for g in _gws) == ["192.168.1.1", "192.168.2.1", "fe80::1"] and _known is True, f"{_gws}")
ds.subprocess.run = _gw_run("", "", fail=True)
try:
    _gws, _known = ds.default_gateways()
finally:
    ds.subprocess.run = REAL_RUN
check("gateways are reported unknown when ip is missing", _gws == [] and _known is False)
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.2.1"], "eth0", "nftables", True, False, False), gateways=(("192.168.1.1", "192.168.2.1"), True))
check("a second default gateway is protected too", isinstance(_r, ValueError) and "gateway" in str(_r) and not _ran)
_r, _ran = _with_apply_env(lambda: _real_apply(["fd00::1"], "eth0", "nftables", True, False, False), gateways=(("fd00:0:0:0::1",), True))
check("an IPv6 gateway written another way is still recognised", isinstance(_r, ValueError) and not _ran)
_gw_log = io.StringIO()
_gw_handler = ds.logging.StreamHandler(_gw_log); ds.logger.addHandler(_gw_handler)
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5"], "eth0", "nftables", True, False, False), gateways=((), False))
ds.logger.removeHandler(_gw_handler)
check("unknown gateways: the run continues but says the check could not run", isinstance(_r, dict) and "could not be read" in _gw_log.getvalue(), _gw_log.getvalue()[:200])

print("Every target is validated before anything changes")
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5", "fe80::1%eth0"], "eth0", "nftables", True, False, False))
check("a zoned link-local target aborts before any command", isinstance(_r, ValueError) and not _ran, f"r={_r} ran={_ran}")
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5", "not-an-ip"], "eth0", "nftables", True, False, False))
check("an invalid address aborts before any command", isinstance(_r, ValueError) and not _ran)
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5", "::ffff:192.168.1.6"], "eth0", "nftables", True, False, False))
check("a mapped address aborts before any command", isinstance(_r, ValueError) and not _ran)
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.001.5" if False else "192.168.1.5", "192.168.1.5"], "eth0", "nftables", True, False, False))
check("duplicate targets become one rule", isinstance(_r, dict) and _r["applied"] == 1, f"r={_r}")

print("Exit 3 means needs-root only")
def _raise_perm(ips, wan, backend, dry_run, force, backup, routed=False):
    raise PermissionError("[Errno 13] Permission denied: '/somewhere/backup.rules'")
def _raise_root(ips, wan, backend, dry_run, force, backup, routed=False):
    raise ds.NeedsRoot("Firewall modification requires root privileges (run with sudo).")
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run", "--wan", "eth0"], {"apply_firewall_rules": _raise_perm, "detect_firewall_backend": lambda p: "nftables"})
check("an ordinary permission error exits 1", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["fix", "192.168.1.5", "--dry-run", "--wan", "eth0"], {"apply_firewall_rules": _raise_root, "detect_firewall_backend": lambda p: "nftables"})
check("a needs-root refusal exits 3", _rc == 3, f"rc={_rc}")
def _export_denied(results, path):
    raise PermissionError("[Errno 13] Permission denied: 'out.json'")
_rc, _o = run_main(["scan", "192.168.1.0/30", "-o", "out.json"], {"scan_targets": _scan_stub([]), "export_results": _export_denied})
check("an unwritable output file exits 1, not 3", _rc == 1, f"rc={_rc}")

print("Text from devices and from Shodan cannot drive the terminal")
check("clean_text replaces control characters", ds.clean_text("ok\x1b[31mred\x07\r\nend") == "ok?[31mred???end")
check("clean_text caps the length and leaves non-strings alone", len(ds.clean_text("x" * 5000)) == ds.TEXT_LIMIT and ds.clean_text(80) == 80)
def _esc_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/" else 403); self.end_headers()
            self.wfile.write(b"\x1b]0;owned\x07<html>Danfoss StoreView\x1b[2J</html>")
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]
ds.PORTS = [_esc_server()]
r = ds.scan_host("127.0.0.1", 2.0, 0)
ds.PORTS = ORIG["PORTS"]
check("the stored page snippet has no control characters", r is not None and r["body_snippet"] and not any(ord(ch) < 32 or ord(ch) == 127 for ch in r["body_snippet"]), f"r={r}")

print("Shodan results are checked against --net by the tool itself")
_mixed = {"matches": [{"ip_str": "8.8.8.5", "port": 80, "data": "StoreView", "org": "Mine\x1b[31m"},
                      {"ip_str": "9.9.9.9", "port": 80, "data": "StoreView", "org": "Someone else"},
                      {"ip_str": "not-an-ip", "port": "80", "data": 5, "org": None},
                      "garbage"], "total": 4}
ds.urllib.request.urlopen = _shodan_fake(_mixed)
_saved_env2 = os.environ.pop("SHODAN_API_KEY", None)
try:
    _res, _ok, _trunc, _outside = ds.shodan_lookup("KEY", "8.8.8.0/28", True)
    _rc, _o = run_main(["shodan", "--api-key", "KEY", "--net", "8.8.8.0/28", "--authorized"])
    ds.SHODAN_MAX_BYTES, _cap = 10, ds.SHODAN_MAX_BYTES
    try:
        _big_res, _big_ok, _bt, _bo = ds.shodan_lookup("KEY", "8.8.8.0/28", True)
    finally:
        ds.SHODAN_MAX_BYTES = _cap
finally:
    ds.urllib.request.urlopen = _orig_urlopen
    if _saved_env2 is not None:
        os.environ["SHODAN_API_KEY"] = _saved_env2
check("results outside --net are dropped and counted", _ok and [r["ip"] for r in _res] == ["8.8.8.5"] and _outside == 2, f"res={_res} outside={_outside}")
check("an org name with escape codes is cleaned", "\x1b" not in _res[0]["org"])
check("a lookup that returned out-of-range results exits 1 and never prints them", _rc == 1 and "9.9.9.9" not in _o and "outside" in _o, f"rc={_rc}")
check("an oversized Shodan answer is refused", _big_res is None and _big_ok is False)
check("multicast, reserved and unspecified ranges are refused", _refuses("224.0.0.0/24", True) and _refuses("240.0.0.0/24", True) and _refuses("0.0.0.0/32", True))

print("Not being root is reported as exit 3 before anything else can fail")
_blocked = TMP / "blocked-file"
_blocked.write_text("x")
_nr = {"data_dir": lambda: _blocked / "data", "log_file": lambda: _blocked / "data" / "danfoss-shield.log",
       "detect_firewall_backend": lambda p: "nftables", "_tool_present": lambda t: True}
with contextlib.redirect_stderr(io.StringIO()):
    _rc_rb, _o_rb = run_main(["fix", "--rollback"], _nr)
    _rc_ap, _o_ap = run_main(["fix", "192.168.1.5", "--wan", "eth0"], _nr)
check("non-root rollback exits 3 even when the data dir cannot be created", _rc_rb == 3 and "requires root" in _o_rb, f"rc={_rc_rb} out={_o_rb[-200:]}")
check("non-root apply exits 3 even when the data dir cannot be created", _rc_ap == 3 and "requires root" in _o_ap, f"rc={_rc_ap} out={_o_ap[-200:]}")
ds.setup_logging(verbose=False, quiet=False, no_color=True)

print("One fix or rollback at a time")
try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None
if _fcntl is None:
    check("lock is POSIX-only (skipped on Windows)", True)
else:
    (TMP / "data").mkdir(parents=True, exist_ok=True)
    _lfd = os.open(str(TMP / "data" / "fix.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    _fcntl.flock(_lfd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    _rb_stub = {"rollback_all": lambda dry: {"removed": 1, "failed": 0, "backends": 1, "saved_files": []},
                "is_root": lambda: True}
    _rc_locked, _o_locked = run_main(["fix", "--rollback"], _rb_stub)
    _rc_dry, _o = run_main(["fix", "--rollback", "--dry-run"], _rb_stub)
    _rc_nonroot, _o = run_main(["fix", "--rollback"], dict(_rb_stub, is_root=lambda: False))
    os.close(_lfd)
    _rc_free, _o = run_main(["fix", "--rollback"], _rb_stub)
    check("a non-root run does not touch the lock (the root check answers first)", _rc_nonroot == 0, f"rc={_rc_nonroot}")
    check("a second run is refused while the lock is held", _rc_locked == 1 and "Another danfoss-shield" in _o_locked, f"rc={_rc_locked}")
    check("a dry-run does not need the lock", _rc_dry == 0, f"rc={_rc_dry}")
    check("the lock is free again afterwards", _rc_free == 0, f"rc={_rc_free}")

print("Silent addresses are told apart from errors")
class _NoAnswerConn:
    sock = None
    def __init__(self, exc): self.exc = exc; self.closed = False
    def connect(self): raise self.exc
    def close(self): self.closed = True
def _state_for(exc):
    conn = _NoAnswerConn(exc)
    ds._connect = lambda h, p, t: conn
    try:
        return ds.probe_port("192.0.2.1", 80, 1.0, 0)[2], conn.closed
    finally:
        ds._connect = ORIG["_connect"]
check("a connect timeout is 'silent'", _state_for(TimeoutError("timed out")) == ("silent", True))
check("host unreachable is 'silent'", _state_for(OSError(_errno.EHOSTUNREACH, "No route to host")) == ("silent", True))
check("network unreachable is 'silent'", _state_for(OSError(_errno.ENETUNREACH, "Network is unreachable")) == ("silent", True))
check("a refused connect is 'refused'", _state_for(ConnectionRefusedError("refused")) == ("refused", True))
check("a reset connect is 'error', not silent", _state_for(ConnectionResetError("reset")) == ("error", True))
check("a TLS failure after the TCP connect is 'error', not silent", ds.probe_port("127.0.0.1", p_err, 1.0, 0)[2] == "error")
ds._connect = lambda h, p, t: _NoAnswerConn(TimeoutError("timed out"))
r = ds.scan_host("192.0.2.1", 1.0, 0)
ds._connect = ORIG["_connect"]
check("a host that never answers on any port is marked silent", r is not None and r.get("probe_error") and r.get("silent") is True, f"r={r}")
_mix = {"n": 0}
def _mixed_connect(h, p, t):
    _mix["n"] += 1
    return _NoAnswerConn(TimeoutError("timed out") if _mix["n"] % 2 else ConnectionResetError("reset"))
ds._connect = _mixed_connect
r = ds.scan_host("192.0.2.1", 1.0, 0)
ds._connect = ORIG["_connect"]
check("a host with silent AND errored ports is not marked silent", r is not None and r.get("probe_error") and r.get("silent") is False, f"r={r}")
def _scan_stub_silent(found, silent, probe_errors=0):
    def stub(targets, workers, timeout, rate_limit, max_hosts, authorized=False):
        return list(found), {"unresolved": [], "total": 9, "probe_errors": probe_errors, "silent": silent}
    return stub
_rc, _o = run_main(["scan", "192.168.1.0/29"], {"scan_targets": _scan_stub_silent([], 5)})
check("silent addresses fail the run by default and are printed", _rc == 1 and "never answered on any port: 5 (state unknown)" in _o, f"rc={_rc}")
_rc, _o = run_main(["scan", "192.168.1.0/29", "--silent-ok"], {"scan_targets": _scan_stub_silent([], 5)})
check("--silent-ok: silent addresses do not fail the run but are still printed", _rc == 0 and "never answered on any port: 5" in _o and "--silent-ok" in _o, f"rc={_rc}")
_rc, _o = run_main(["scan", "192.168.1.0/29", "--silent-ok"], {"scan_targets": _scan_stub_silent([], 5, probe_errors=1)})
check("--silent-ok does not hide real probe errors", _rc == 1, f"rc={_rc}")
_rc, _o = run_main(["check", "192.168.1.5", "--silent-ok"], {"scan_targets": _scan_stub_silent([], 1)})
check("check accepts --silent-ok", _rc == 0, f"rc={_rc}")
_open = [{"ip": "192.168.1.5", "port": 80, "controller": "Danfoss StoreView", "match": "StoreView", "auth": "open"}]
_rc, _o = run_main(["scan", "192.168.1.0/29", "--silent-ok"], {"scan_targets": _scan_stub_silent(_open, 5)})
check("--silent-ok never hides an open controller (exit 2)", _rc == 2, f"rc={_rc}")
_applied.clear()
_rc, _o = run_main(["fix", "--all", "192.168.1.0/29", "--dry-run"], dict(_fixp, scan_targets=_scan_stub_silent(_open, 3)))
check("fix --all: silent addresses make the run partial by default (exit 1, controller still blocked)", _rc == 1 and _applied == [["192.168.1.5"]], f"rc={_rc}")
_applied.clear()
_rc, _o = run_main(["fix", "--all", "192.168.1.0/29", "--dry-run", "--silent-ok"], dict(_fixp, scan_targets=_scan_stub_silent(_open, 3)))
check("fix --all --silent-ok: exit 0 when only silent addresses were incomplete", _rc == 0 and _applied == [["192.168.1.5"]], f"rc={_rc}")
_rc, _o = run_main(["fix", "--all", "192.168.1.0/29", "--dry-run", "--silent-ok"], dict(_fixp, scan_targets=_scan_stub_silent([], 3)))
check("fix --all --silent-ok with nothing found and only silence exits 0", _rc == 0, f"rc={_rc}")

print("Timer command and unit file")
_argv = ds._exec_start("192.168.1.0/24", TMP / "scans")
check("the timer's scan uses --silent-ok and still parses", "--silent-ok" in _argv and ds._parse_check(_argv[2:])[0])
check("systemd specifiers and variables are escaped in ExecStart",
      ds.systemd_exec_line(["/opt/100%/py", "/home/a$b/tool.py", "scan"]) == "/opt/100%%/py '/home/a$$b/tool.py' scan",
      ds.systemd_exec_line(["/opt/100%/py", "/home/a$b/tool.py", "scan"]))

print("CSV keeps every column")
_csv2 = TMP / "union.csv"
ds.export_results([{"ip": "192.168.1.5", "port": 80, "auth": "closed"},
                   {"ip": "192.168.1.6", "port": 80, "auth": "unknown", "partial_probe": [443]}], str(_csv2))
_csv_txt = _csv2.read_text()
check("a column that only a later row has is exported", "partial_probe" in _csv_txt.splitlines()[0] and "[443]" in _csv_txt, _csv_txt)
_empty_csv = TMP / "empty.csv"
ds.export_results([], str(_empty_csv))
check("an empty result set still writes a header", _empty_csv.read_text().startswith("ip,port,controller,auth,timestamp"))

print("Numbers on the command line and in the config are validated")
_stub_ok = {"scan_targets": _scan_stub([])}
for _label, _argv in (("--timeout 0", ["scan", "10.0.0.1", "--timeout", "0"]), ("--timeout abc", ["scan", "10.0.0.1", "--timeout", "abc"]),
                      ("--timeout nan", ["scan", "10.0.0.1", "--timeout", "nan"]), ("--timeout 9999", ["scan", "10.0.0.1", "--timeout", "9999"]),
                      ("--workers 0", ["scan", "10.0.0.1", "--workers", "0"]), ("--workers 999", ["scan", "10.0.0.1", "--workers", "999"]),
                      ("--workers 2.5", ["scan", "10.0.0.1", "--workers", "2.5"]), ("--rate-limit -1", ["scan", "10.0.0.1", "--rate-limit", "-1"]),
                      ("check --timeout -3", ["check", "10.0.0.1", "--timeout", "-3"])):
    _rc, _o = run_main(_argv, _stub_ok)
    check(f"{_label} is refused with exit 1", _rc == 1 and "must be a number between" in _o, f"rc={_rc}")
_rc, _o = run_main(["scan", "10.0.0.1", "--timeout", "0.5", "--workers", "8", "--rate-limit", "0"], _stub_ok)
check("valid numbers are accepted (rate limit 0 = no limit)", _rc == 0, f"rc={_rc} {_o[-200:]}")
(TMP / "cfg").mkdir(parents=True, exist_ok=True)
_cfgf = TMP / "cfg" / "config"
_cfgf.write_text("[danfoss-shield]\ntimeout = abc\nworkers = -5\nrate_limit = 1e9\nsubnet = 10.9.8.0/24\n")
with contextlib.redirect_stderr(io.StringIO()) as _cfg_err:
    _cfg = ds.load_config()
check("junk numbers in the config fall back to defaults, good values are kept",
      _cfg["timeout"] == "3.0" and _cfg["workers"] == "30" and _cfg["rate_limit"] == "20.0" and _cfg["subnet"] == "10.9.8.0/24", f"{_cfg}")
check("each ignored config value is named on stderr", all(k in _cfg_err.getvalue() for k in ("timeout", "workers", "rate_limit")))
_rc, _o = run_main(["scan", "10.0.0.1"], _stub_ok)
check("the tool starts with a junk config instead of crashing", _rc == 0, f"rc={_rc} {_o[-300:]}")
_cfgf.write_text("timeout = 5\nthis file has no section header\n")
with contextlib.redirect_stderr(io.StringIO()) as _cfg_err:
    _cfg = ds.load_config()
check("an unparseable config file is ignored with a message", _cfg == ds.CONFIG_DEFAULTS and "Config file ignored" in _cfg_err.getvalue(), f"{_cfg}")
_cfgf.write_text("[danfoss-shield]\ntimeout = 7.5\nworkers = 12\n")
_cfg = ds.load_config()
_ns = ds.build_parser(_cfg)[-1].parse_args(["scan"])
check("valid config numbers reach the parser defaults", _ns.timeout == 7.5 and _ns.workers == 12, f"{_ns}")
_cfgf.unlink()

print("Ctrl+C ends cleanly")
def _interrupt(*a, **k):
    raise KeyboardInterrupt()
_rc, _o = run_main(["scan", "10.0.0.1"], {"scan_targets": _interrupt})
check("interrupting a scan exits 1 with a plain message", _rc == 1 and "Interrupted" in _o and "Traceback" not in _o, f"rc={_rc}")
_rc, _o = run_main(["fix", "192.168.1.5", "--wan", "eth0"], {"apply_firewall_rules": _interrupt, "detect_firewall_backend": lambda p: "nftables"})
check("interrupting fix says the firewall may be in a partial state and how to roll back", _rc == 1 and "partial state" in _o and "--rollback" in _o, f"rc={_rc}")
_rc, _o = run_main(["fix", "192.168.1.5", "--wan", "eth0", "--dry-run"], {"apply_firewall_rules": _interrupt, "detect_firewall_backend": lambda p: "nftables"})
check("interrupting a dry-run does not claim a partial state", _rc == 1 and "partial state" not in _o, f"rc={_rc}")
_t0 = _time.monotonic()
_rc, _o = run_main(["scan", "127.0.0.1", "10.255.255.1", "--timeout", "0.3", "--rate-limit", "0", "-w", "2"], {"scan_host": _interrupt})
check("an interrupt raised inside a worker stops the scan with exit 1", _rc == 1 and "Interrupted" in _o and _time.monotonic() - _t0 < 10, f"rc={_rc}")
check("the stop flag is cleared for the next scan", (ds.scan_targets(["127.0.0.1"], 1, 2.0, 0, 16) or True) and not ds.stop_scan.is_set())

print("Small boundaries")
_raised_empty = False
try:
    ds.resolve_target("   ", 16)
except ValueError:
    _raised_empty = True
check("an empty target is refused instead of scanning this machine", _raised_empty)
_rc, _o = run_main(["scan", ""])
check("scan '' exits 1", _rc == 1, f"rc={_rc}")
_over = False
try:
    ds.resolve_target("10.0.0.0/21", ds.MAX_FIX_HOSTS)
except ValueError:
    _over = True
_ips_cap, _ok_cap = ds.resolve_target("10.0.0.0/22", ds.MAX_FIX_HOSTS)
check("the fix cap of 1024 addresses holds: /21 refused, /22 accepted", _over and _ok_cap and len(_ips_cap) == 1022, f"over={_over} n={len(_ips_cap)}")
_applied.clear()
_rc, _o = run_main(["fix", "10.0.0.0/21", "--dry-run"], _fixp)
check("fix on a range over the cap exits 1 and applies nothing", _rc == 1 and not _applied, f"rc={_rc}")
_big = "x" * (1024 * 1024 + 7)
_wf = TMP / "big.txt"
ds._safe_write_text(_wf, _big)
check("_safe_write_text writes all of a large text", _wf.stat().st_size == len(_big) and _wf.read_text() == _big)
_saved_nc = os.environ.pop("NO_COLOR", None)
try:
    with contextlib.redirect_stdout(io.StringIO()):
        ds.setup_logging(verbose=False, quiet=False, no_color=False)
        _no_tty_colors = ds.colors.disabled
finally:
    os.environ["NO_COLOR"] = _saved_nc if _saved_nc is not None else "1"
check("colour codes are off when the output is not a terminal", _no_tty_colors is True)
ds.setup_logging(verbose=False, quiet=False, no_color=True)

print("A TLS server that answers slowly after the handshake")
_openssl = _shutil.which("openssl")
if not _openssl:
    check("TLS slow-answer test needs openssl (skipped here)", True)
else:
    _key, _crt = TMP / "k.pem", TMP / "c.pem"
    _gen = REAL_RUN([_openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(_key), "-out", str(_crt),
                     "-days", "1", "-subj", "/CN=localhost"], capture_output=True, text=True)
    if _gen.returncode != 0 or not _crt.exists():
        check("TLS slow-answer test: openssl could not make a certificate (skipped)", True)
    else:
        _sctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER); _sctx.load_cert_chain(str(_crt), str(_key))
        def _tls_answer_server(mode):
            srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
            stop = threading.Event()
            def serve_one(raw):
                try:
                    raw.settimeout(5)
                    conn = _sctx.wrap_socket(raw, server_side=True)
                except Exception:
                    raw.close(); return
                try:
                    conn.settimeout(2)
                    try:
                        conn.recv(4096)
                    except OSError:
                        pass
                    if mode == "body":
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                    for _ in range(600):
                        if stop.is_set():
                            break
                        conn.sendall(b"x")
                        stop.wait(0.1)
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
            def loop():
                while not stop.is_set():
                    try:
                        c, _ = srv.accept()
                    except OSError:
                        return
                    threading.Thread(target=serve_one, args=(c,), daemon=True).start()
            threading.Thread(target=loop, daemon=True).start()
            return srv, srv.getsockname()[1], stop
        ds.PROBE_DEADLINE_MIN = 1.5
        for _mode in ("body", "headers"):
            _srv, _port, _stop = _tls_answer_server(_mode)
            ds.SSL_PORTS = (_port,)
            _t0 = _time.monotonic()
            _b, _c, _st = ds.probe_port("127.0.0.1", _port, 0.5, 0)
            _dt = _time.monotonic() - _t0
            check(f"TLS slow-drip {_mode} after the handshake: the watchdog ends the probe at the deadline",
                  _st == "error" and 1.3 <= _dt <= 4.0, f"state={_st} elapsed={_dt:.2f}s")
            _hit = False
            try:
                ds._fetch("127.0.0.1", _port, "/", 0.5, 65536)
            except ds.ProbeDeadline:
                _hit = True
            except Exception as _ex:
                _hit = type(_ex).__name__
            check(f"TLS slow-drip {_mode}: _fetch raises ProbeDeadline", _hit is True, f"got={_hit}")
            _stop.set(); _srv.close()
        ds.SSL_PORTS = ORIG["SSL_PORTS"]
        ds.PROBE_DEADLINE_MIN = ORIG["PROBE_DEADLINE_MIN"]

print("--silent-ok has a floor")
def _scan_stub_total(found, total, silent, probe_errors=0):
    def stub(targets, workers, timeout, rate_limit, max_hosts, authorized=False):
        return list(found), {"unresolved": [], "total": total, "probe_errors": probe_errors, "silent": silent}
    return stub
check("scan_incomplete: all addresses silent is incomplete even with --silent-ok",
      ds.scan_incomplete({"unresolved": [], "total": 254, "probe_errors": 0, "silent": 254}, True) is True)
check("scan_incomplete: some silence with --silent-ok is complete",
      ds.scan_incomplete({"unresolved": [], "total": 254, "probe_errors": 0, "silent": 253}, True) is False)
check("scan_incomplete: an empty target list is not 'nothing answered'",
      ds.scan_incomplete({"unresolved": [], "total": 0, "probe_errors": 0, "silent": 0}, True) is False)
check("nothing_answered: false when there was nothing to scan",
      ds.nothing_answered({"unresolved": ["no-such-host"], "total": 0, "probe_errors": 0, "silent": 0}) is False)
check("nothing_answered: true when every scanned address was silent",
      ds.nothing_answered({"unresolved": [], "total": 6, "probe_errors": 0, "silent": 6}) is True)
_rc, _o = run_main(["scan", "10.9.9.0/29", "--silent-ok"], {"scan_targets": _scan_stub_total([], 6, 6)})
check("scan --silent-ok where nothing answered exits 1 and says so", _rc == 1 and "No address answered at all" in _o, f"rc={_rc}")
_applied.clear()
_rc, _o = run_main(["fix", "--all", "10.9.9.0/29", "--dry-run", "--silent-ok"], dict(_fixp, scan_targets=_scan_stub_total([], 6, 6)))
check("fix --all --silent-ok where nothing answered exits 1", _rc == 1 and not _applied and "No address answered at all" in _o, f"rc={_rc}")
_rc, _o = run_main(["scan", "10.9.9.0/29", "--silent-ok"], {"scan_targets": _scan_stub_total([], 6, 5)})
check("scan --silent-ok where one address answered and had no controller exits 0", _rc == 0, f"rc={_rc}")

print("Ctrl+C is prompt")
_dsrv, _dport, _dstop = _drip_server("body")
_res_box = {}
def _probe_bg():
    _t = _time.monotonic()
    _res_box["state"] = ds.probe_port("127.0.0.1", _dport, 5.0, 0)[2]
    _res_box["dt"] = _time.monotonic() - _t
ds.stop_scan.clear()
_th = threading.Thread(target=_probe_bg, daemon=True); _th.start()
_time.sleep(0.5)
ds.stop_scan.set()
_th.join(5)
ds.stop_scan.clear()
_dstop.set(); _dsrv.close()
check("a probe in flight is abandoned soon after the stop flag is set (deadline would be 15 s)",
      not _th.is_alive() and _res_box.get("state") == "error" and _res_box.get("dt", 99) < 3.0, f"{_res_box}")
ds.next_request_slot = _time.monotonic() + 30
ds.stop_scan.set()
_t0 = _time.monotonic()
ds.enforce_rate_limit(1.0)
_waited = _time.monotonic() - _t0
ds.stop_scan.clear()
ds.next_request_slot = 0.0
check("the rate limiter does not sit out its wait once the stop flag is set", _waited < 1.0, f"waited={_waited:.2f}s")
_rc, _o = run_main(["scan", "10.0.0.1", "--rate-limit", "0.001"], _stub_ok)
check("a non-zero rate limit below 0.1 is refused", _rc == 1 and "or 0 for no limit" in _o, f"rc={_rc}")
_rc, _o = run_main(["scan", "10.0.0.1", "--rate-limit", "0.1"], _stub_ok)
check("rate limit 0.1 is accepted", _rc == 0, f"rc={_rc}")
check("a config rate below 0.1 is not accepted", ds._in_range(float, "0.05", ds.RATE_RANGE) is False and ds._in_range(float, "0", ds.RATE_RANGE) is True)

print("A timed-out command says its effect is unknown")
_to_log = io.StringIO()
_to_handler = ds.logging.StreamHandler(_to_log); ds.logger.addHandler(_to_handler)
ds.subprocess.run = _hang_run
try:
    _ok_to = ds._run(["iptables", "-I", "FORWARD", "-j", "DROP"], dry_run=False)
finally:
    ds.subprocess.run = REAL_RUN
    ds.logger.removeHandler(_to_handler)
check("the message says the command was stopped and its effect is unknown",
      _ok_to is False and "did not finish" in _to_log.getvalue() and "effect is unknown" in _to_log.getvalue()
      and "could not be started" not in _to_log.getvalue(), _to_log.getvalue()[:200])

print("Gateways and the host's own addresses")
ds.subprocess.run = _gw_run("default via inet6 fe80::1 dev eth0\n", "")
try:
    _gws, _known = ds.default_gateways()
finally:
    ds.subprocess.run = REAL_RUN
check("an IPv6 next hop for an IPv4 route (via inet6 ...) is found", [str(g) for g in _gws] == ["fe80::1"] and _known is True, f"{_gws} {_known}")
ds.subprocess.run = _gw_run("default via something-odd dev eth0\n", "")
try:
    _gws, _known = ds.default_gateways()
finally:
    ds.subprocess.run = REAL_RUN
check("a gateway that cannot be parsed makes the result 'unknown', not silently empty", _gws == [] and _known is False)
def _addr_run(cmd, **kw):
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
           "2: eth0    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever\n"
           "2: eth0    inet6 fd00::1/64 scope global \\       valid_lft forever\n"
           "3: wan0    inet 8.8.8.9/29 scope global wan0\\       valid_lft forever\n")
    return subprocess.CompletedProcess(list(cmd), 0, out, "")
ds.subprocess.run = _addr_run
try:
    _own, _own_known = ds.host_addresses()
finally:
    ds.subprocess.run = REAL_RUN
check("the host's own addresses are read", sorted(str(a) for a in _own) == ["127.0.0.1", "192.168.1.1", "8.8.8.9", "fd00::1"] and _own_known, f"{_own}")
ds.subprocess.run = _missing_tool
try:
    _own, _own_known = ds.host_addresses()
finally:
    ds.subprocess.run = REAL_RUN
check("own addresses are 'unknown' when ip is missing", _own == [] and _own_known is False)
_r, _ran = _with_apply_env(lambda: _real_apply(["8.8.8.9"], "eth0", "nftables", True, False, False, routed=True), own=(("8.8.8.9", "192.168.1.1"), True))
check("--routed refuses one of this host's own addresses before any command", isinstance(_r, ValueError) and "this host itself" in str(_r) and not _ran, f"r={_r}")
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.1"], "eth0", "nftables", True, False, False), own=(("192.168.1.1",), True))
check("a private address of this host is refused too", isinstance(_r, ValueError) and not _ran)
_own_log = io.StringIO()
_own_handler = ds.logging.StreamHandler(_own_log); ds.logger.addHandler(_own_handler)
_r, _ran = _with_apply_env(lambda: _real_apply(["192.168.1.5"], "eth0", "nftables", True, False, False), own=((), False))
ds.logger.removeHandler(_own_handler)
check("unknown own addresses: the run continues and says the check could not run", isinstance(_r, dict) and "own addresses could not be read" in _own_log.getvalue())

print("An unwritable data dir must not block rollback")
if _fcntl is None:
    check("lock fallback is POSIX-only (skipped on Windows)", True)
else:
    _rb_ok = {"rollback_all": lambda dry: {"removed": 1, "failed": 0, "backends": 1, "saved_files": []},
              "is_root": lambda: True, "data_dir": lambda: _blocked / "data", "log_file": lambda: _blocked / "data" / "danfoss-shield.log"}
    with contextlib.redirect_stderr(io.StringIO()):
        _rc, _o = run_main(["fix", "--rollback"], _rb_ok)
    check("rollback proceeds without the lock when the lock file cannot be created", _rc == 0 and "continuing without it" in _o, f"rc={_rc} out={_o[-200:]}")
    ds.setup_logging(verbose=False, quiet=False, no_color=True)

print("Version and CI permissions")
check("VERSION is 1.0.1", ds.VERSION == "1.0.1")
_wf =HERE.parent / ".github" / "workflows" / "tests.yml"
_wf_txt = _wf.read_text(encoding="utf-8") if _wf.exists() else ""
check("CI workflow declares read-only permissions", "permissions:" in _wf_txt and "contents: read" in _wf_txt)

for _name, _val in ORIG.items():
    setattr(ds, _name, _val)
ds.setup_logging(verbose=False, quiet=False, no_color=True)

print("Nothing is left open")
gc.collect()
check("no unclosed socket or file was reported during the whole run", not LEAKS, f"{len(LEAKS)} leak(s): {LEAKS[:4]}")

passed = sum(1 for _,ok,_ in results if ok)
total = len(results)
print(f"\n==== {passed}/{total} passed ====")
sys.exit(0 if passed == total else 1)
