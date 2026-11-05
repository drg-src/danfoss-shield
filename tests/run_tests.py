import importlib.util, io, json, os, socket, subprocess, sys, tempfile, threading, types, contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "danfoss_shield.py"
TMP = Path(tempfile.mkdtemp(prefix="ds103_"))
os.environ["NO_COLOR"] = "1"

spec = importlib.util.spec_from_file_location("ds", SRC)
ds = importlib.util.module_from_spec(spec); spec.loader.exec_module(ds)

ds.data_dir = lambda: TMP / "data"
ds.config_dir = lambda: TMP / "cfg"
ds.config_file = lambda: TMP / "cfg" / "config"
ds.log_file = lambda: TMP / "data" / "danfoss-shield.log"
ds.is_root = lambda: False

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

print("Finding 1: key redaction")
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

print("Finding 2: CIDR cap")
try:
    ds.resolve_target("10.0.0.0/8", ds.MAX_SCAN_HOSTS); check("refuse /8", False, "no raise")
except ValueError: check("refuse /8", True)
try:
    ds.resolve_target("2001:db8::/64", ds.MAX_SCAN_HOSTS); check("refuse IPv6 /64", False, "no raise")
except ValueError: check("refuse IPv6 /64", True)
ips, ok = ds.resolve_target("192.168.1.0/30", ds.MAX_SCAN_HOSTS)
check("accept small /30", ok and len(ips) == 2, f"ips={ips}")

print("Finding 8: honest scan states")
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
ds.PORTS = [deadp]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("all-ports-error -> probe_error unknown", r is not None and r.get("probe_error") and r["auth"] == ds.AUTH_UNKNOWN)
ds.PORTS = orig_ports

env = dict(os.environ, NO_COLOR="1", USERPROFILE=str(TMP), HOME=str(TMP))
dead = free_port()
rc = subprocess.run([sys.executable,"-I",str(SRC),"scan","127.0.0.1","--rate-limit","0","--timeout","1","-w","4"],
                    capture_output=True, text=True, env=env)
check("dead scan exits non-zero", rc.returncode != 0, f"rc={rc.returncode}")

print("Finding 9: rollback both backends")
def fake_run_factory(state):
    def fake_run(cmd, **kw):
        c = cmd if isinstance(cmd, list) else [cmd]
        joined = " ".join(c)
        rc = 0; out = ""
        if c[0] in ("nft","iptables","ip6tables") and "--version" in c:
            rc = 0 if ((c[0]=="nft" and state["nft"]) or (c[0] in ("iptables","ip6tables") and state["ipt"])) else 0
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
import subprocess as _sp; ds.subprocess.run = _sp.run
ds.is_root = lambda: False

print("Finding 10: systemd scan command")
argv = ds._exec_start("192.168.1.0/24", TMP/"scans")
ok_new, err_new = ds._parse_check(argv[2:])
check("generated command (--quiet before scan) parses", ok_new, err_new)
ok_old, _ = ds._parse_check(["scan","192.168.1.0/24","--quiet","--output","x.json"])
check("old order (scan ... --quiet) is rejected", not ok_old)

print("Finding 6: systemd config validation")
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

print("Finding 4: CSV sanitisation")
out_csv = TMP/"out.csv"
ds.export_results([{"ip":"1.2.3.4","port":80,"controller":"=cmd|' /C calc'!A1","auth":"open","org":"+SUM(1)"}], str(out_csv))
csv_txt = out_csv.read_text()
check("leading = neutralised", "'=cmd" in csv_txt, csv_txt)
check("leading + neutralised", "'+SUM" in csv_txt, csv_txt)

print("Finding 11: fix target guards")
try:
    ds.require_authorized(["8.8.8.8"], False); check("require_authorized refuses public w/o flag", False)
except ValueError: check("require_authorized refuses public w/o flag", True)
ds.require_authorized(["192.168.1.9"], False); check("require_authorized allows private", True)
ds.get_default_gateway_ip = lambda: None
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

print("Finding 3: file permissions")
if os.name == "posix":
    mode = oct(os.stat(ds.data_dir()).st_mode & 0o777)
    check("data dir is 0700", mode == "0o700", mode)
    lm = oct(os.stat(ds.log_file()).st_mode & 0o777)
    check("log file is 0600", lm == "0o600", lm)
else:
    check("perms are POSIX-only (skipped on Windows)", True, "SKIP")


print("v1.0.4: --api abbreviation")
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
_ns = _abbr_parser.parse_args(["shodan", "--api-key", "REALKEY"])
check("`shodan --api-key X` still accepted", _ns.api_key == "REALKEY")

print("v1.0.4: closed+errored -> unknown")
deadp2 = free_port()
ds.PORTS = [p_clo, deadp2]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("closed finding + errored port -> unknown", r is not None and r["auth"] == ds.AUTH_UNKNOWN and r.get("partial_probe"), f"r={r}")
ds.PORTS = [p_open, deadp2]
r = ds.scan_host("127.0.0.1", 1.0, 0)
check("open finding NOT downgraded by errored port", r is not None and r["auth"] == ds.AUTH_OPEN)
ds.PORTS = orig_ports

print("v1.0.4: fingerprints")
check("generic Emerson/Copeland dropped", b"Emerson" not in ds.DIXELL_FINGERPRINTS and b"Copeland" not in ds.DIXELL_FINGERPRINTS and b"Dixell" in ds.DIXELL_FINGERPRINTS)

print("v1.0.4: 200 html heuristic")
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

print("v1.0.4: >4KB fingerprint")
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

print("v1.0.4: txt sanitisation")
out_txt = TMP/"out.txt"
ds.export_results([{"ip":"=HYPERLINK(1)","port":80,"controller":"Danfoss","auth":"open"}], str(out_txt))
check("txt sink neutralises leading =", "'=HYPERLINK" in out_txt.read_text())

print("v1.0.4: rollback guards")
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
ds.subprocess.run = _sp.run
ds.is_root = lambda: False

print("v1.0.4: ip6tables-save in snapshot")
_saved = []
def _cap_save_run(cmd, **kw):
    c = cmd if isinstance(cmd, list) else [cmd]
    _saved.append(c[0]); return subprocess.CompletedProcess(c, 0, "rules\n", "")
ds.subprocess.run = _cap_save_run
ds.save_applied_rules("iptables")
ds.subprocess.run = _sp.run
check("save_applied_rules runs ip6tables-save too", "ip6tables-save" in _saved and "iptables-save" in _saved, f"calls={_saved}")

print("v1.0.4: shodan error-json")
class _FakeResp:
    def __init__(self, data): self._d = data.encode()
    def read(self): return self._d
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

print("v1.0.4: logging degrades when data dir is uncreatable")
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

passed = sum(1 for _,ok,_ in results if ok)
total = len(results)
print(f"\n==== {passed}/{total} passed ====")
sys.exit(0 if passed == total else 1)
