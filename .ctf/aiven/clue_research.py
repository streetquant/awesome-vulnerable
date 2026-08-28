#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import html
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OUT=Path('probe-output/clues')
OUT.mkdir(parents=True,exist_ok=True)
UA='Aiven-CTF-authorized-clue-research/1.0'
STARTED=dt.datetime.now(dt.timezone.utc).isoformat()
TERMS=[
    'CVE-2026-46242',
    'customOpLibrary',
    'v83_service_instance_boundary_arguments_invalid',
    'v83_supervisor_status_reconcile_permanently_disabled',
    'service_instance_boundary predecessor cleanup',
    'execute_maybe_sent root_entered private_key_recovered',
]


def utcnow(): return dt.datetime.now(dt.timezone.utc).isoformat()
def sha256(b:bytes): return hashlib.sha256(b).hexdigest()

def fetch(label:str,url:str,accept='application/json,text/html,text/plain,*/*',timeout=40)->dict[str,Any]:
    row={'label':label,'url':url,'observed_at':utcnow()}
    req=urllib.request.Request(url,headers={'User-Agent':UA,'Accept':accept})
    try:
        with urllib.request.urlopen(req,timeout=timeout,context=ssl.create_default_context()) as r:
            b=r.read(10_000_000)
            row.update({'status':r.status,'final_url':r.geturl(),'headers':dict(r.headers.items()),'body_b64':base64.b64encode(b).decode(),'body_bytes':len(b),'body_sha256':sha256(b)})
    except Exception as e: row['error']=f'{type(e).__name__}: {e}'
    return row

def text(row):
    try:return base64.b64decode(row.get('body_b64','')).decode('utf-8','replace')
    except Exception:return ''

def compact_html(raw:str)->str:
    raw=re.sub(r'(?is)<script.*?</script>|<style.*?</style>',' ',raw)
    raw=re.sub(r'(?s)<[^>]+>',' ',raw)
    return re.sub(r'\s+',' ',html.unescape(raw)).strip()

def snippets(raw:str,term:str,window=500)->list[str]:
    clean=compact_html(raw)
    out=[]
    low=clean.lower(); needle=term.lower(); pos=0
    while len(out)<8:
        i=low.find(needle,pos)
        if i<0: break
        out.append(clean[max(0,i-window):min(len(clean),i+len(term)+window)])
        pos=i+len(term)
    return out

urls={
 'mitre_cve':'https://cveawg.mitre.org/api/cve/CVE-2026-46242',
 'nvd_cve':'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-46242',
 'github_advisories':'https://api.github.com/advisories?cve_id=CVE-2026-46242',
}
for i,term in enumerate(TERMS):
    q=urllib.parse.quote('"'+term+'"')
    urls[f'duckduckgo_{i}']='https://html.duckduckgo.com/html/?q='+q
    urls[f'bing_{i}']='https://www.bing.com/search?q='+q
    urls[f'github_code_{i}']='https://api.github.com/search/code?q='+urllib.parse.quote('"'+term+'"')+'&per_page=20'
rows={k:fetch(k,u) for k,u in urls.items()}

parsed={}
for key in ('mitre_cve','nvd_cve','github_advisories'):
    raw=text(rows[key])
    try: parsed[key]=json.loads(raw)
    except Exception as e: parsed[key]={'parse_error':f'{type(e).__name__}: {e}','text_prefix':compact_html(raw)[:2000]}

search_findings={}
for i,term in enumerate(TERMS):
    vals=[]
    for engine in ('duckduckgo','bing','github_code'):
        row=rows[f'{engine}_{i}']; raw=text(row)
        vals.append({'source':engine,'status':row.get('status'),'error':row.get('error'),'snippets':snippets(raw,term)})
    search_findings[term]=vals

report={'schema':'aiven-ctf-clue-research-v1','run_started_utc':STARTED,'run_finished_utc':utcnow(),'runner':{'repository':os.environ.get('GITHUB_REPOSITORY'),'run_id':os.environ.get('GITHUB_RUN_ID'),'sha':os.environ.get('GITHUB_SHA')},'terms':TERMS,'sources':rows,'parsed':parsed,'search_findings':search_findings}
raw=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode(); (OUT/'clue-research.json').write_bytes(raw)

def cve_summary():
    out={'exists':False,'descriptions':[],'affected':[],'references':[]}
    m=parsed.get('mitre_cve',{})
    if isinstance(m,dict) and m.get('cveMetadata'):
        out['exists']=True
        cna=(m.get('containers') or {}).get('cna') or {}
        out['descriptions']=[x.get('value') for x in cna.get('descriptions',[]) if x.get('value')]
        out['affected']=[{'vendor':x.get('vendor'),'product':x.get('product'),'versions':x.get('versions')} for x in cna.get('affected',[])]
        out['references']=[x.get('url') for x in cna.get('references',[]) if x.get('url')]
    n=parsed.get('nvd_cve',{})
    try:
        vulns=n.get('vulnerabilities',[])
        if vulns:
            out['exists']=True
            c=vulns[0]['cve']
            out['descriptions'] += [x.get('value') for x in c.get('descriptions',[]) if x.get('value')]
            out['references'] += [x.get('url') for x in c.get('references',[]) if x.get('url')]
    except Exception: pass
    out['descriptions']=list(dict.fromkeys(out['descriptions']))
    out['references']=list(dict.fromkeys(out['references']))
    return out
summary={'schema':'aiven-ctf-clue-research-summary-v1','run_started_utc':STARTED,'run_finished_utc':report['run_finished_utc'],'cve_2026_46242':cve_summary(),'term_hit_counts':{term:sum(len(x['snippets']) for x in vals) for term,vals in search_findings.items()},'source_statuses':{k:{'status':v.get('status'),'error':v.get('error'),'bytes':v.get('body_bytes'),'sha256':v.get('body_sha256')} for k,v in rows.items()},'report_sha256':sha256(raw)}
sraw=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode(); (OUT/'summary.json').write_bytes(sraw)
(OUT/'manifest.json').write_text(json.dumps({'schema':'aiven-ctf-clue-research-manifest-v1','created_at_utc':utcnow(),'files':[{'path':'clue-research.json','bytes':len(raw),'sha256':sha256(raw)},{'path':'summary.json','bytes':len(sraw),'sha256':sha256(sraw)}]},indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
