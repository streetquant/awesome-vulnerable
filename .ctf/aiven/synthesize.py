#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT=Path('.ctf/aiven/results')
OUT=Path('probe-output/synthesis');OUT.mkdir(parents=True,exist_ok=True)

def load(path:Path)->dict[str,Any]|None:
    try:return json.loads(path.read_text())
    except Exception:return None

def latest(pattern:str)->tuple[str,dict[str,Any]]|None:
    rows=[]
    for p in ROOT.rglob(pattern):
        d=load(p)
        if d is not None: rows.append((str(p),d))
    return rows[-1] if rows else None

def sha(b:bytes):return hashlib.sha256(b).hexdigest()

items={
 'deep':latest('deep_summary.json') or latest('*deep*summary*.json'),
 'interface':latest('summary.json'),
 'clues':latest('github-clue-search.json'),
 'clue_summary':latest('*clue*summary*.json'),
}
# Select interface by schema rather than filename collision.
for p in ROOT.rglob('*.json'):
    d=load(p)
    if not d:continue
    s=d.get('schema','')
    if s=='aiven-ctf-interface-probe-v1':items['interface']=(str(p),d)
    elif s=='aiven-ctf-github-clue-search-summary-v1':items['clue_summary']=(str(p),d)
    elif s=='aiven-ctf-clue-research-summary-v1':items['web_clue_summary']=(str(p),d)
    elif s=='aiven-ctf-deep-target-derived-recon-v1':items['deep']=(str(p),d)

def val(name):return items.get(name,(None,{}))[1] if items.get(name) else {}
deep=val('deep');interface=val('interface');clue=val('clue_summary');webclue=val('web_clue_summary')
open_ports=interface.get('open_ports_by_ip') or deep.get('open_ports_by_ip') or {}
open_ports={ip:ports for ip,ports in open_ports.items() if ports}
trust=int(interface.get('trust_auth_sessions') or 0)
classifications=interface.get('postgres_classifications') or []
cve=(webclue.get('cve_2026_46242') or {})
query_counts=clue.get('query_counts') or {}

if trust>0:
    state='unauthenticated_postgresql_session_observed'
    next_action='Use the private encrypted extraction workflow to attempt the exact target-side key read and target-side external-IP command, then validate with ssh-keygen.'
elif open_ports:
    state='live_target_derived_interface_observed'
    next_action='Inspect raw interface evidence for protocol/version and resume the matching exploit path; do not return to generic discovery.'
elif deep.get('passive_candidate_ip_count'):
    state='passive_candidates_found_but_no_live_interface_in_sanitized_summary'
    next_action='Reconcile target activation/current assignment and mine private workspace evidence for current credentials and service-instance identity before replaying side-effectful operations.'
else:
    state='no_current_target_resolution_or_live_interface_observed'
    next_action='Recover the current assigned service instance from the private workspace/Bugcrowd session; historical IP replay is exhausted.'

synthesis={'schema':'aiven-ctf-synthesis-v1','created_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'source_files':{k:v[0] for k,v in items.items() if v},'state':state,'open_ports_by_ip':open_ports,'postgres_classifications':classifications,'trust_auth_sessions':trust,'cve_2026_46242':cve,'github_query_counts':query_counts,'next_action':next_action,'solved':False,'missing':['fresh target key bytes','target provenance for exact key read','ssh-keygen validation','current target-attributed external IP','reproducible exploit chain']}
raw=(json.dumps(synthesis,indent=2,sort_keys=True)+'\n').encode();(OUT/'summary.json').write_bytes(raw)
(OUT/'manifest.json').write_text(json.dumps({'schema':'aiven-ctf-synthesis-manifest-v1','created_at_utc':synthesis['created_at_utc'],'files':[{'path':'summary.json','bytes':len(raw),'sha256':sha(raw)}]},indent=2,sort_keys=True)+'\n')
print(json.dumps(synthesis,sort_keys=True))
