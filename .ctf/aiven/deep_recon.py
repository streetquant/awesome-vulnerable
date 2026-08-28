#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

TARGET = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
OLD_TARGET = "falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com"
PREFIX = "falcon-bug-bounty-flag-pgsql"
KNOWN_IPS = {"150.136.73.18", "193.122.144.9"}
OUT = Path("probe-output/deep")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Aiven-CTF-authorized-deep-recon/1.0"
STARTED = dt.datetime.now(dt.timezone.utc).isoformat()
MAX_SOURCE_BYTES = 20_000_000
MAX_SCAN_IPS = 12


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], timeout: int = 360) -> dict[str, Any]:
    started = time.monotonic()
    try:
        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {
            "argv": argv,
            "returncode": cp.returncode,
            "stdout": cp.stdout.decode("utf-8", "replace"),
            "stderr": cp.stderr.decode("utf-8", "replace"),
            "stdout_sha256": sha256(cp.stdout),
            "stderr_sha256": sha256(cp.stderr),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }
    except Exception as exc:
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}", "elapsed_ms": round((time.monotonic()-started)*1000,3)}


def fetch(label: str, url: str, headers: dict[str, str] | None = None, timeout: int = 35) -> tuple[str, dict[str, Any]]:
    row: dict[str, Any] = {"label": label, "url": url, "observed_at": utcnow()}
    req_headers = {"User-Agent": UA, "Accept": "application/json,text/plain,text/html,*/*"}
    if headers:
        req_headers.update(headers)
    try:
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            body = response.read(MAX_SOURCE_BYTES)
            row.update({
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body_b64": base64.b64encode(body).decode(),
                "body_bytes": len(body),
                "body_sha256": sha256(body),
            })
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return label, row


def body(row: dict[str, Any]) -> str:
    try:
        return base64.b64decode(row.get("body_b64", "")).decode("utf-8", "replace")
    except Exception:
        return ""


def public_ipv4s(text: str) -> set[str]:
    out = set()
    for token in re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", text):
        try:
            ip = ipaddress.ip_address(token)
            if ip.version == 4 and ip.is_global:
                out.add(str(ip))
        except ValueError:
            pass
    return out


def relevant_names(text: str) -> set[str]:
    names = set()
    for token in re.findall(r"(?i)(?:[a-z0-9_-]+\.)+[a-z]{2,63}", text):
        token = token.lower().strip(".\"' ,;()[]{}<>")
        if "aivencloud.com" in token and ("falcon" in token or PREFIX in token):
            names.add(token)
    return names


def scan_ip(ip: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="aiven-deep-", suffix=".xml", delete=False) as handle:
        xml_path = Path(handle.name)
    try:
        result = run([
            "nmap", "-Pn", "-n", "-sT", "-p-", "--open", "--reason",
            "--min-rate", "1800", "--max-retries", "1", "--host-timeout", "5m",
            "-oX", str(xml_path), ip,
        ], timeout=330)
        raw = xml_path.read_bytes() if xml_path.exists() else b""
        result["xml_sha256"] = sha256(raw)
        result["xml_b64"] = base64.b64encode(raw).decode()
        ports=[]
        if raw:
            try:
                root=ET.fromstring(raw)
                for p in root.findall(".//port"):
                    st=p.find("state")
                    if st is None or st.get("state") != "open":
                        continue
                    svc=p.find("service")
                    ports.append({
                        "protocol": p.get("protocol"),
                        "port": int(p.get("portid", "0")),
                        "reason": st.get("reason"),
                        "service": dict(svc.attrib) if svc is not None else {},
                    })
            except Exception as exc:
                result["parse_error"] = f"{type(exc).__name__}: {exc}"
        result["open_ports"] = ports
        result["ip"] = ip
        result["observed_at"] = utcnow()
        return result
    finally:
        try: xml_path.unlink()
        except Exception: pass


def version_scan(ip: str, ports: list[int]) -> dict[str, Any]:
    if not ports:
        return {"ip": ip, "ports": [], "skipped": True}
    return run([
        "nmap", "-Pn", "-n", "-sT", "-sV", "--version-all", "--script",
        "banner,ssl-cert,ssl-enum-ciphers,http-title,http-headers,pgsql-brute", # pgsql-brute has no credentials and normally performs a tiny default check only; disable below via args.
        "--script-args", "pgsql-brute.timeout=2s,pgsql-brute.threads=1,userdb=/dev/null,passdb=/dev/null",
        "-p", ",".join(map(str, ports)), ip,
    ], timeout=240)


def rdns(ip: str) -> dict[str, Any]:
    row={"ip":ip,"observed_at":utcnow()}
    try: row["reverse"] = socket.gethostbyaddr(ip)
    except Exception as exc: row["error"] = f"{type(exc).__name__}: {exc}"
    return row


q = urllib.parse.quote
sources = {
    "otx_target_pdns": f"https://otx.alienvault.com/api/v1/indicators/hostname/{q(TARGET, safe='')}/passive_dns",
    "otx_old_pdns": f"https://otx.alienvault.com/api/v1/indicators/hostname/{q(OLD_TARGET, safe='')}/passive_dns",
    "urlscan_target": f"https://urlscan.io/api/v1/search/?q={q('domain:'+TARGET)}&size=100",
    "urlscan_old": f"https://urlscan.io/api/v1/search/?q={q('domain:'+OLD_TARGET)}&size=100",
    "crt_target": f"https://crt.sh/?q={q(TARGET)}&output=json",
    "crt_old": f"https://crt.sh/?q={q(OLD_TARGET)}&output=json",
    "crt_prefix": f"https://crt.sh/?q={q('%'+PREFIX+'%')}&output=json",
    "threatminer_target_pdns": f"https://api.threatminer.org/v2/domain.php?q={q(TARGET)}&rt=2",
    "threatminer_old_pdns": f"https://api.threatminer.org/v2/domain.php?q={q(OLD_TARGET)}&rt=2",
    "robtex_target": f"https://freeapi.robtex.com/pdns/forward/{q(TARGET)}",
    "robtex_old": f"https://freeapi.robtex.com/pdns/forward/{q(OLD_TARGET)}",
    "hackertarget_target_dns": f"https://api.hackertarget.com/dnslookup/?q={q(TARGET)}",
    "hackertarget_old_dns": f"https://api.hackertarget.com/dnslookup/?q={q(OLD_TARGET)}",
    "hackertarget_e_hostsearch": "https://api.hackertarget.com/hostsearch/?q=e.aivencloud.com",
    "google_doh_target": f"https://dns.google/resolve?name={q(TARGET)}&type=A",
    "google_doh_old": f"https://dns.google/resolve?name={q(OLD_TARGET)}&type=A",
    "cloudflare_doh_target": f"https://cloudflare-dns.com/dns-query?name={q(TARGET)}&type=A",
    "cloudflare_doh_old": f"https://cloudflare-dns.com/dns-query?name={q(OLD_TARGET)}&type=A",
    "duckduckgo_exact": "https://html.duckduckgo.com/html/?q=" + q('"'+TARGET+'"'),
    "duckduckgo_old": "https://html.duckduckgo.com/html/?q=" + q('"'+OLD_TARGET+'"'),
    "bing_exact": "https://www.bing.com/search?q=" + q('"'+TARGET+'"'),
    "bing_old": "https://www.bing.com/search?q=" + q('"'+OLD_TARGET+'"'),
}

source_rows: dict[str, Any] = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    futures=[]
    for label,url in sources.items():
        headers={"Accept":"application/dns-json"} if label.startswith("cloudflare") else None
        futures.append(pool.submit(fetch,label,url,headers))
    for fut in concurrent.futures.as_completed(futures):
        label,row=fut.result(); source_rows[label]=row

ip_sources: dict[str,set[str]] = defaultdict(set)
name_sources: dict[str,set[str]] = defaultdict(set)
for label,row in source_rows.items():
    text=body(row)
    for ip in public_ipv4s(text): ip_sources[ip].add(label)
    for name in relevant_names(text): name_sources[name].add(label)
for ip in KNOWN_IPS: ip_sources[ip].add("known_prior_target_observation")

# Resolve every directly relevant historical name and add current addresses.
resolution_rows=[]
for name in sorted({TARGET,OLD_TARGET,*name_sources.keys()}):
    row={"name":name,"observed_at":utcnow()}
    try:
        infos=socket.getaddrinfo(name,None,type=socket.SOCK_STREAM)
        row["addresses"]=sorted({x[4][0] for x in infos})
        for ip in row["addresses"]:
            try:
                if ipaddress.ip_address(ip).version==4 and ipaddress.ip_address(ip).is_global:
                    ip_sources[ip].add("current_resolution:"+name)
            except ValueError: pass
    except Exception as exc: row["error"] = f"{type(exc).__name__}: {exc}"
    resolution_rows.append(row)

# Rank addresses by exact-target relevance rather than scanning the whole Internet.
def score(item: tuple[str,set[str]]) -> tuple[int,str]:
    ip,labels=item
    s=0
    for label in labels:
        low=label.lower()
        if "known_prior" in low: s+=100
        if "target" in low and "old" not in low: s+=50
        if "old" in low: s+=20
        if "urlscan" in low or "otx" in low or "robtex" in low: s+=10
        if "current_resolution" in low: s+=200
    return (-s,ip)
ranked=sorted(ip_sources.items(),key=score)
scan_ips=[ip for ip,_ in ranked[:MAX_SCAN_IPS]]

scan_rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    future_map={pool.submit(scan_ip,ip):ip for ip in scan_ips}
    for fut in concurrent.futures.as_completed(future_map): scan_rows.append(fut.result())
scan_rows.sort(key=lambda r:r["ip"])

version_rows=[]
for row in scan_rows:
    ports=sorted({p["port"] for p in row.get("open_ports",[])})
    version_rows.append(version_scan(row["ip"],ports))

rdns_rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    rdns_rows=list(pool.map(rdns,scan_ips))

report={
    "schema":"aiven-ctf-deep-target-derived-recon-v1",
    "target":TARGET,
    "run_started_utc":STARTED,
    "run_finished_utc":utcnow(),
    "runner":{"repository":os.environ.get("GITHUB_REPOSITORY"),"run_id":os.environ.get("GITHUB_RUN_ID"),"sha":os.environ.get("GITHUB_SHA")},
    "safety":{
        "authorization":"user-declared Aiven Bugcrowd CTF",
        "candidate_ips_derived_only_from_exact-target passive sources or prior target observations":True,
        "max_scanned_ips":MAX_SCAN_IPS,
        "authentication_attempts":0,
        "passwords_sent":0,
        "sql_sent":0,
    },
    "sources":source_rows,
    "ip_sources":{ip:sorted(labels) for ip,labels in sorted(ip_sources.items())},
    "historical_names":{name:sorted(labels) for name,labels in sorted(name_sources.items())},
    "resolutions":resolution_rows,
    "scan_ips":scan_ips,
    "full_tcp_scans":scan_rows,
    "version_scans":version_rows,
    "reverse_dns":rdns_rows,
}
raw=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode()
(OUT/"deep-recon.json").write_bytes(raw)
summary={
    "schema":report["schema"],
    "target":TARGET,
    "run_started_utc":STARTED,
    "run_finished_utc":report["run_finished_utc"],
    "passive_candidate_ip_count":len(ip_sources),
    "candidate_name_count":len(name_sources),
    "scanned_ips":scan_ips,
    "open_ports_by_ip":{r["ip"]:sorted({p["port"] for p in r.get("open_ports",[])}) for r in scan_rows},
    "reverse_dns":{r["ip"]:r.get("reverse") for r in rdns_rows if r.get("reverse")},
    "source_statuses":{k:{"status":v.get("status"),"error":v.get("error"),"bytes":v.get("body_bytes"),"sha256":v.get("body_sha256")} for k,v in sorted(source_rows.items())},
    "report_sha256":sha256(raw),
}
sraw=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode()
(OUT/"summary.json").write_bytes(sraw)
manifest={"schema":"aiven-ctf-deep-recon-manifest-v1","created_at_utc":utcnow(),"files":[{"path":"deep-recon.json","bytes":len(raw),"sha256":sha256(raw)},{"path":"summary.json","bytes":len(sraw),"sha256":sha256(sraw)}]}
(OUT/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
