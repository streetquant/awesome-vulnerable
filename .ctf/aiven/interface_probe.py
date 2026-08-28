#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

TARGET='falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com'
OLD_TARGET='falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com'
KNOWN_IPS=['150.136.73.18','193.122.144.9']
RESULT_ROOT=Path('.ctf/aiven/results')
OUT=Path('probe-output/interfaces'); OUT.mkdir(parents=True,exist_ok=True)
STARTED=dt.datetime.now(dt.timezone.utc).isoformat()
TIMEOUT=6.0
MAX_RESPONSE=256*1024


def utcnow(): return dt.datetime.now(dt.timezone.utc).isoformat()
def sha256(b:bytes): return hashlib.sha256(b).hexdigest()

def run(argv:list[str],timeout:int=30,env:dict[str,str]|None=None)->dict[str,Any]:
    started=time.monotonic()
    try:
        cp=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=env)
        return {'argv':argv,'returncode':cp.returncode,'stdout':cp.stdout.decode('utf-8','replace'),'stderr':cp.stderr.decode('utf-8','replace'),'stdout_sha256':sha256(cp.stdout),'stderr_sha256':sha256(cp.stderr),'elapsed_ms':round((time.monotonic()-started)*1000,3)}
    except Exception as e:return {'argv':argv,'error':f'{type(e).__name__}: {e}','elapsed_ms':round((time.monotonic()-started)*1000,3)}

def recv_exact(s:socket.socket,n:int)->bytes:
    out=[]
    while n:
        c=s.recv(n)
        if not c: raise EOFError('unexpected EOF')
        out.append(c); n-=len(c)
    return b''.join(out)

def pg_first(ip:str,port:int,sni:str|None,user:str,db:str)->dict[str,Any]:
    row={'ip':ip,'port':port,'sni':sni,'user':user,'database':db,'observed_at':utcnow(),'password_messages_sent':0,'sql_sent':0}
    raw=tls=None
    try:
        raw=socket.create_connection((ip,port),timeout=TIMEOUT); raw.settimeout(TIMEOUT)
        raw.sendall(struct.pack('!II',8,80877103)); r=recv_exact(raw,1); row['ssl_response']=r.hex()
        if r!=b'S': row['classification']='not_postgresql_tls'; return row
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        ctx.set_alpn_protocols(['postgresql'])
        tls=ctx.wrap_socket(raw,server_hostname=sni);raw=None;tls.settimeout(TIMEOUT)
        der=tls.getpeercert(binary_form=True) or b''
        row.update({'tls_version':tls.version(),'cipher':list(tls.cipher() or ()),'selected_alpn':tls.selected_alpn_protocol(),'certificate_sha256':sha256(der)})
        params=b'user\x00'+user.encode()+b'\x00database\x00'+db.encode()+b'\x00application_name\x00aiven-ctf-interface-probe\x00client_encoding\x00UTF8\x00\x00'
        pkt=struct.pack('!II',8+len(params),196608)+params;tls.sendall(pkt)
        typ=recv_exact(tls,1);length=struct.unpack('!I',recv_exact(tls,4))[0];payload=recv_exact(tls,length-4)
        msg={'type':typ.decode('ascii','replace'),'length':length,'payload_b64':base64.b64encode(payload).decode(),'payload_sha256':sha256(payload)}
        if typ==b'R' and len(payload)>=4:
            code=struct.unpack('!I',payload[:4])[0]; msg['auth_code']=code;msg['auth_name']={0:'AuthenticationOk',3:'AuthenticationCleartextPassword',5:'AuthenticationMD5Password',10:'AuthenticationSASL'}.get(code,'Other')
        elif typ==b'E': msg['error_text']=payload.decode('utf-8','replace')
        row['first_message']=msg;row['classification']=msg.get('auth_name','postgres_response')
    except Exception as e:row['classification']='probe_error';row['error']=f'{type(e).__name__}: {e}'
    finally:
        for s in (tls,raw):
            try:
                if s:s.close()
            except Exception:pass
    return row

def http_probe(ip:str,port:int,tls_mode:bool,path:str,sni:str)->dict[str,Any]:
    row={'ip':ip,'port':port,'tls':tls_mode,'path':path,'sni':sni,'observed_at':utcnow()};raw=s=None
    try:
        raw=socket.create_connection((ip,port),timeout=TIMEOUT);raw.settimeout(TIMEOUT)
        if tls_mode:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            s=ctx.wrap_socket(raw,server_hostname=sni);raw=None;row['certificate_sha256']=sha256(s.getpeercert(binary_form=True) or b'')
        else:s=raw;raw=None
        req=f'GET {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Aiven-CTF-authorized-interface-probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'.encode();s.sendall(req)
        chunks=[];total=0
        while total<MAX_RESPONSE:
            try:c=s.recv(min(8192,MAX_RESPONSE-total))
            except socket.timeout:break
            if not c:break
            chunks.append(c);total+=len(c)
        data=b''.join(chunks);row['response_bytes']=len(data);row['response_sha256']=sha256(data);row['response_b64']=base64.b64encode(data).decode();row['response_prefix']=data.decode('utf-8','replace')[:12000]
    except Exception as e:row['error']=f'{type(e).__name__}: {e}'
    finally:
        for x in (s,raw):
            try:
                if x:x.close()
            except Exception:pass
    return row

def load_candidates()->dict[str,list[int]]:
    found:dict[str,set[int]]={ip:set() for ip in KNOWN_IPS}
    for p in RESULT_ROOT.rglob('*summary.json') if RESULT_ROOT.exists() else []:
        try:d=json.loads(p.read_text())
        except Exception:continue
        for ip,ports in (d.get('open_ports_by_ip') or {}).items():
            try:
                if not ipaddress.ip_address(ip).is_global:continue
            except Exception:continue
            found.setdefault(ip,set()).update(int(x) for x in ports)
        for ip in d.get('scanned_ips') or []:
            try:
                if ipaddress.ip_address(ip).is_global:found.setdefault(ip,set())
            except Exception:pass
    # Recheck a compact common/known service set even if summaries were unavailable.
    defaults={22,80,443,5432,6432,8443,9090,12691,12692,25060}
    for ip in found:found[ip].update(defaults)
    return {ip:sorted(ports) for ip,ports in found.items()}

candidates=load_candidates()
# Bounded reachability recheck.
reach=[]
for ip,ports in candidates.items():
    for port in ports:
        row={'ip':ip,'port':port,'observed_at':utcnow()}
        try:
            with socket.create_connection((ip,port),timeout=2.5) as s:row['open']=True
        except Exception as e:row['open']=False;row['error']=f'{type(e).__name__}: {e}'
        reach.append(row)
open_by_ip={}
for r in reach:
    if r.get('open'):open_by_ip.setdefault(r['ip'],[]).append(r['port'])

pg=[];http=[];ssh=[]
for ip,ports in sorted(open_by_ip.items()):
    for port in sorted(set(ports)):
        for sni in (TARGET,OLD_TARGET,None):
            for user,db in (('avnadmin','defaultdb'),('postgres','postgres'),('ctf_probe_nonexistent','postgres')):
                pg.append(pg_first(ip,port,sni,user,db))
        for tls_mode in (False,True):
            for path in ('/','/health','/status','/version','/metrics','/api','/v1','/swagger','/openapi.json','/.well-known/openid-configuration'):
                http.append(http_probe(ip,port,tls_mode,path,TARGET))
        if port==22 or any('SSH-' in (x.get('response_prefix') or '') for x in http[-20:]):
            ssh.append(run(['ssh-keyscan','-T','5','-p',str(port),ip],timeout=12))

# A true trust-auth path is queried with psql, but never send a password and never read the requested secret here.
psql=[]
for row in pg:
    if row.get('classification')!='AuthenticationOk':continue
    ip=row['ip'];port=row['port'];host=row.get('sni') or TARGET;user=row['user'];db=row['database']
    conn=f'host={host} hostaddr={ip} port={port} user={user} dbname={db} sslmode=require connect_timeout=5'
    sql="""SELECT json_build_object(
      'version',version(),
      'current_user',current_user,
      'database',current_database(),
      'server_addr',inet_server_addr()::text,
      'server_port',inet_server_port(),
      'is_superuser',(SELECT usesuper FROM pg_user WHERE usename=current_user),
      'read_server_files',pg_has_role(current_user,'pg_read_server_files','MEMBER'),
      'execute_server_program',pg_has_role(current_user,'pg_execute_server_program','MEMBER'),
      'read_file_execute',has_function_privilege(current_user,'pg_catalog.pg_read_file(text)','EXECUTE')
    );
    SELECT extname||':'||extversion FROM pg_extension ORDER BY 1;
    SELECT n.nspname||'.'||p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE lower(p.proname) SIMILAR TO '%(aiven|custom|library|execute|program|file)%' ORDER BY 1 LIMIT 500;
    """
    env=dict(os.environ);env.pop('PGPASSWORD',None)
    res=run(['psql',conn,'-X','-v','ON_ERROR_STOP=1','-At','-c',sql],timeout=30,env=env)
    res.update({'ip':ip,'port':port,'host':host,'user':user,'database':db,'password_sent':False,'requested_secret_read':False});psql.append(res)

report={'schema':'aiven-ctf-interface-probe-v1','target':TARGET,'run_started_utc':STARTED,'run_finished_utc':utcnow(),'runner':{'repository':os.environ.get('GITHUB_REPOSITORY'),'run_id':os.environ.get('GITHUB_RUN_ID'),'sha':os.environ.get('GITHUB_SHA')},'safety':{'scope':'authorized exact target-derived IPs only','password_messages_sent':0,'secret_file_reads':0,'sql_sent_only_after_authentication_ok_without_password':True,'brute_force':False},'candidates':candidates,'reachability':reach,'open_ports_by_ip':open_by_ip,'postgresql':pg,'http':http,'ssh_keyscan':ssh,'trust_auth_sql':psql}
raw=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode();(OUT/'interface-probe.json').write_bytes(raw)
summary={'schema':report['schema'],'target':TARGET,'run_started_utc':STARTED,'run_finished_utc':report['run_finished_utc'],'open_ports_by_ip':open_by_ip,'postgres_classifications':sorted({r.get('classification','unknown') for r in pg}),'trust_auth_sessions':len(psql),'http_responses':sum(1 for r in http if r.get('response_bytes')),'ssh_keyscan_attempts':len(ssh),'report_sha256':sha256(raw)}
sraw=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode();(OUT/'summary.json').write_bytes(sraw)
(OUT/'manifest.json').write_text(json.dumps({'schema':'aiven-ctf-interface-probe-manifest-v1','created_at_utc':utcnow(),'files':[{'path':'interface-probe.json','bytes':len(raw),'sha256':sha256(raw)},{'path':'summary.json','bytes':len(sraw),'sha256':sha256(sraw)}]},indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
