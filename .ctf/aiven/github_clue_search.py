#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OUT=Path('probe-output/github-clues'); OUT.mkdir(parents=True,exist_ok=True)
TOKEN=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
API='https://api.github.com'
UA='Aiven-CTF-authorized-github-clue-search/1.0'
STARTED=dt.datetime.now(dt.timezone.utc).isoformat()
QUERIES=[
    '"customOpLibrary"',
    '"CVE-2026-46242"',
    '"service_instance_boundary"',
    '"supervisor_status_reconcile"',
    '"pre_registration_before"',
    '"execute_maybe_sent"',
    '"root_entered" "private_key_recovered"',
    '"falcon-bug-bounty-flag-pgsql"',
]


def utcnow():return dt.datetime.now(dt.timezone.utc).isoformat()
def sha256(b:bytes):return hashlib.sha256(b).hexdigest()

def request(url:str,accept='application/vnd.github+json')->dict[str,Any]:
    row={'url':url,'observed_at':utcnow()};headers={'User-Agent':UA,'Accept':accept,'X-GitHub-Api-Version':'2022-11-28'}
    if TOKEN:headers['Authorization']='Bearer '+TOKEN
    try:
        req=urllib.request.Request(url,headers=headers)
        with urllib.request.urlopen(req,timeout=45,context=ssl.create_default_context()) as r:
            b=r.read(20_000_000);row.update({'status':r.status,'headers':dict(r.headers.items()),'body_b64':base64.b64encode(b).decode(),'body_bytes':len(b),'body_sha256':sha256(b)})
    except Exception as e:row['error']=f'{type(e).__name__}: {e}'
    return row

def json_body(row):
    try:return json.loads(base64.b64decode(row.get('body_b64','')).decode('utf-8','replace'))
    except Exception:return None

def text_body(row):
    try:return base64.b64decode(row.get('body_b64','')).decode('utf-8','replace')
    except Exception:return ''

def contexts(text:str,needles:list[str],window=600)->list[str]:
    out=[];low=text.lower()
    for needle in needles:
        pos=0;n=needle.lower().strip('"')
        while len(out)<16:
            i=low.find(n,pos)
            if i<0:break
            out.append(text[max(0,i-window):min(len(text),i+len(n)+window)])
            pos=i+len(n)
    return list(dict.fromkeys(out))

raw_searches={};findings=[]
for query in QUERIES:
    for kind,endpoint in [('code','search/code'),('issues','search/issues'),('commits','search/commits')]:
        url=f'{API}/{endpoint}?q='+urllib.parse.quote(query)+'&per_page=50'
        accept='application/vnd.github.text-match+json' if kind=='code' else 'application/vnd.github+json'
        row=request(url,accept);raw_searches[f'{kind}:{query}']=row;data=json_body(row)
        if not isinstance(data,dict):continue
        for item in data.get('items',[])[:50]:
            f={'query':query,'kind':kind,'html_url':item.get('html_url'),'repository_url':item.get('repository_url'),'name':item.get('name'),'path':item.get('path'),'sha':item.get('sha'),'title':item.get('title'),'text_matches':item.get('text_matches')}
            findings.append(f)
        time.sleep(0.2)

# Fetch unique matching public source files and preserve bounded contexts.
file_contexts=[];seen=set()
for f in findings:
    if f['kind']!='code':continue
    repo_url=f.get('repository_url') or ''
    m=re.search(r'/repos/([^/]+/[^/]+)$',repo_url)
    if not m or not f.get('path'):continue
    key=(m.group(1),f['path'],f.get('sha'))
    if key in seen:continue
    seen.add(key)
    if len(seen)>100:break
    url=f"{API}/repos/{m.group(1)}/contents/{urllib.parse.quote(f['path'],safe='/')}?ref={urllib.parse.quote(f.get('sha') or '')}"
    row=request(url);data=json_body(row);text=''
    if isinstance(data,dict) and data.get('content'):
        try:text=base64.b64decode(data['content']).decode('utf-8','replace')
        except Exception:pass
    file_contexts.append({'repository':m.group(1),'path':f['path'],'sha':f.get('sha'),'html_url':f.get('html_url'),'fetch_status':row.get('status'),'fetch_error':row.get('error'),'content_sha256':sha256(text.encode()),'contexts':contexts(text,QUERIES)})

report={'schema':'aiven-ctf-github-clue-search-v1','run_started_utc':STARTED,'run_finished_utc':utcnow(),'runner':{'repository':os.environ.get('GITHUB_REPOSITORY'),'run_id':os.environ.get('GITHUB_RUN_ID'),'sha':os.environ.get('GITHUB_SHA')},'authenticated':bool(TOKEN),'queries':QUERIES,'raw_searches':raw_searches,'findings':findings,'file_contexts':file_contexts}
raw=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode();(OUT/'github-clue-search.json').write_bytes(raw)
summary={'schema':'aiven-ctf-github-clue-search-summary-v1','run_started_utc':STARTED,'run_finished_utc':report['run_finished_utc'],'authenticated':bool(TOKEN),'query_counts':{q:{k:sum(1 for f in findings if f['query']==q and f['kind']==k) for k in ('code','issues','commits')} for q in QUERIES},'top_findings':[{'query':f['query'],'kind':f['kind'],'html_url':f.get('html_url'),'name':f.get('name'),'path':f.get('path'),'title':f.get('title')} for f in findings[:100]],'file_context_count':len(file_contexts),'report_sha256':sha256(raw)}
sraw=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode();(OUT/'summary.json').write_bytes(sraw)
(OUT/'manifest.json').write_text(json.dumps({'schema':'aiven-ctf-github-clue-search-manifest-v1','created_at_utc':utcnow(),'files':[{'path':'github-clue-search.json','bytes':len(raw),'sha256':sha256(raw)},{'path':'summary.json','bytes':len(sraw),'sha256':sha256(sraw)}]},indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
