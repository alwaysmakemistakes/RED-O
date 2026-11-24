#!/usr/bin/env python3
"""RED-O: rule-by-rule replay and opt-in safe Kubernetes live smoke.

Replay: REAL detector binary processes synthetic raw Tetragon/Audit JSONL for
22 enabled rules, with one matching and one non-matching trial per rule.
Live: explicitly enabled K3s/Tetragon exercises, with honest SKIP for missing
policies and R022. Not an attack, exploitation test, or detection quality study.
No third-party Python modules, no credentials collected, no JSONL overwritten.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ALL = [f'R{i:03d}' for i in range(1, 23)]
CORR = {'R005', 'R006', 'R007', 'R008', 'R020'}
UTC = dt.timezone.utc


def stamp():
    return dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')


def utcnow():
    return dt.datetime.now(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def jsonlines(path):
    if not path.is_file():
        return []
    out = []
    with path.open(encoding='utf-8', errors='replace') as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RuntimeError(f'{path}:{i}: invalid JSON: {e}') from e
    return out


def run(args, *, cwd=None, timeout=120, capture=True, check=True):
    p = subprocess.run(args, cwd=cwd, text=True, encoding='utf-8',
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None,
                       timeout=timeout, check=False)
    if check and p.returncode:
        msg = ((p.stderr or '') + '\n' + (p.stdout or '')).strip()
        raise RuntimeError(f'{args[0]} returned {p.returncode}: {msg[-1500:]}')
    return p


def read_rules(root):
    rs = json.loads((root / 'configs/rules.json').read_text(encoding='utf-8'))['rules']
    cs = json.loads((root / 'configs/correlations.json').read_text(encoding='utf-8'))['correlations']
    actual = {r['id'] for r in rs + cs if r['enabled']}
    if actual != set(ALL):
        raise RuntimeError(f'expected enabled R001..R022; missing={sorted(set(ALL)-actual)}, extra={sorted(actual-set(ALL))}')
    return {r['id']: r for r in rs + cs}


class ReplayFactory:
    def __init__(self):
        self.raw = []
        self.cases = []
        self.base = dt.datetime(2026, 11, 21, 10, 0, tzinfo=UTC)

    def raw_time(self, idx, sec):
        return (self.base + dt.timedelta(seconds=idx*70+sec)).isoformat().replace('+00:00','Z')

    def case(self, rid, positive):
        suffix = 'p' if positive else 'n'
        name = f'redo-fixture-{rid.lower()}-{suffix}'
        idx = len(self.cases)
        entry = {'rule_id': rid, 'test_id': name, 'label': 'positive' if positive else 'negative',
                 'pod': name, 'expected_alert': positive, 'expected_events': 0}
        self.cases.append(entry)
        proc = {'exec_id': f'exec-{name}', 'parent_exec_id':'', 'binary':'/usr/bin/python3',
                'arguments':'', 'pod':{'namespace':'security-lab','name':name,'uid':'pod-'+name,
                                     'container':{'id':'containerd://'+name,'name':name,'image':{'name':'lab'}}}}
        t = 0
        def add(kind, binary=None, arguments='', path=None, ip=None, port=443, function=None, priv=None, status=201):
            nonlocal t
            rawtime = self.raw_time(idx, t)
            t += 1
            if kind == 'audit':
                item = {'kind':'Event', 'apiVersion':'audit.k8s.io/v1', 'auditID':str(uuid.uuid4()),
                        'stage':'ResponseComplete', 'stageTimestamp':rawtime, 'verb':'create',
                        'user':{'username':'system:admin'},
                        'objectRef':{'namespace':'security-lab', 'resource':'pods','name':name},
                        'responseStatus':{'code':status}}
            else:
                p = json.loads(json.dumps(proc))
                if binary is not None:
                    p['binary'] = binary
                p['arguments'] = arguments
                if priv:
                    p['binary_properties'] = {'privileges_changed': priv}
                item = {'time':rawtime, 'node_name':'lab-node'}
                if kind == 'exec':
                    item['process_exec']={'process':p}
                else:
                    if kind == 'file':
                        function = function or 'security_file_open'
                        arg = [{'file_arg':{'path':path}}]
                    elif kind == 'net':
                        function = 'tcp_connect'
                        arg = [{'sock_arg':{'family':'AF_INET','protocol':'IPPROTO_TCP','daddr':ip,'dport':port}}]
                    elif kind == 'hook':
                        function = function or 'security_capset'
                        arg = []
                    else:
                        raise ValueError(kind)
                    item['process_kprobe']={'process':p, 'policy_name':'redo-fixture',
                                            'function_name':function,'args':arg}
            self.raw.append(item)
            entry['expected_events'] += 1

        if rid == 'R001':
            add('exec', binary='/bin/sh' if positive else '/bin/true')
        elif rid == 'R002':
            add('file', path='/etc/shadow' if positive else '/etc/hostname')
        elif rid == 'R003':
            add('net', ip='1.1.1.1' if positive else '9.9.9.9', port=443)
        elif rid == 'R004':
            add('exec', binary='/bin/wget' if positive else '/bin/true')
        elif rid == 'R005':
            add('exec', binary='/bin/sh')
            add('file', path='/etc/passwd')
            if positive:
                add('net', ip='1.1.1.1')
        elif rid == 'R006':
            add('exec', binary='/bin/sh')
            if positive:
                add('net', ip='1.1.1.1')
        elif rid == 'R007':
            add('file', path='/run/secrets/kubernetes.io/serviceaccount/..2026_11_21/token')
            if positive:
                add('net', ip='1.1.1.1')
        elif rid == 'R008':
            add('exec', binary='/bin/wget')
            if positive:
                add('net', ip='1.1.1.1')
        elif rid == 'R009':
            add('exec', binary='/bin/sh', arguments='-c true' if positive else '-i')
        elif rid == 'R010':
            add('file', path='/var/run/secrets/kubernetes.io/serviceaccount/..2026_11_21/token' if positive else '/var/run/secrets/kubernetes.io/serviceaccount/..2026_11_21/ca.crt')
        elif rid == 'R011':
            add('hook', function='security_capset' if positive else 'security_inode_permission')
        elif rid == 'R012':
            add('exec', binary='/tmp/unshare' if positive else '/bin/true')
        elif rid == 'R013':
            add('net', ip='10.42.0.25' if positive else '1.1.1.1')
        elif rid == 'R014':
            add('exec', binary='/tmp/xmrig' if positive else '/bin/true')
        elif rid == 'R015':
            add('net', ip='198.51.100.3', port=3333 if positive else 9000)
        elif rid == 'R016':
            add('audit', status=201 if positive else 403)
        elif rid == 'R017':
            add('file', path='/run/docker.sock' if positive else '/tmp/demo.sock')
        elif rid == 'R018':
            add('exec', binary='/tmp/setcap' if positive else '/bin/true')
        elif rid == 'R019':
            add('exec', binary='/tmp/nmap' if positive else '/bin/true')
        elif rid == 'R020':
            add('exec', binary='/bin/sh')
            if positive:
                add('net', ip='10.43.0.33', port=8080)
        elif rid == 'R021':
            for n in range(1, 6 if positive else 5):
                add('net', ip=f'10.42.1.{n}', port=8080)
        elif rid == 'R022':
            add('exec', binary='/usr/bin/python3', priv=['PRIVILEGES_RAISED_EXEC_FILE_SETUID'] if positive else ['PRIVILEGES_DROPPED_EXEC_FILE_CAP'])
        return entry


def make_replay(root, out):
    factory = ReplayFactory()
    for rid in ALL:
        factory.case(rid, True)
        factory.case(rid, False)
    path = out / 'raw-fixtures.jsonl'
    path.write_text(''.join(json.dumps(x, separators=(',', ':')) + '\n' for x in factory.raw), encoding='utf-8')
    save(out / 'trial-plan.json', factory.cases)
    binary = root / 'bin/red-o'
    cmd = [str(binary), 'detector', 'run', '-source','jsonl', '-input',str(path),
           '-mode','forensic', '-rules','configs/rules.json', '-correlations','configs/correlations.json',
           '-correlation-lateness','0', '-events',str(out/'normalized-events.jsonl'),
           '-alerts',str(out/'alerts.jsonl'), '-raw',str(out/'raw.jsonl'),
           '-heartbeat','', '-gap-log','', '-metrics-listen','']
    p = run(cmd, cwd=root, timeout=120, check=False)
    (out/'detector.log').write_text((p.stdout or '')+'\n'+(p.stderr or ''), encoding='utf-8')
    if p.returncode:
        raise RuntimeError(f'detector replay failed ({p.returncode}); see {out/"detector.log"}')
    events, alerts = jsonlines(out/'normalized-events.jsonl'), jsonlines(out/'alerts.jsonl')
    by_pod = {}
    for e in events:
        by_pod.setdefault((e.get('kubernetes') or {}).get('pod'), set()).add(e.get('event_id'))
    rows = []
    for case in factory.cases:
        pod = case['pod']; expected = case['expected_alert']; ids = by_pod.get(pod,set())
        hits = [a for a in alerts if a.get('rule_id') == case['rule_id']
                and (a.get('kubernetes') or {}).get('pod') == pod
                and set(a.get('related_event_ids') or []).issubset(ids)
                and len(a.get('related_event_ids') or []) > 0]
        evidence_ok = bool(hits)
        if case['rule_id'] in CORR:
            evidence_ok = any(len(a.get('related_event_ids') or []) >=
                              (3 if case['rule_id']=='R005' else 2) for a in hits)
        if case['rule_id'] == 'R021':
            evidence_ok = any(len(a.get('related_event_ids') or []) >= 5 for a in hits)
        status = ('PASS' if (len(ids)==case['expected_events'] and
                 ((expected and evidence_ok) or (not expected and not hits))) else 'FAIL')
        rows.append({**case,'status':status,'observed_events':len(ids),
                     'target_alerts':len(hits), 'related_ids_max':max((len(a.get('related_event_ids') or []) for a in hits),default=0)})
        print(f'{status:5} replay {case["rule_id"]} {case["label"]:8}  events={len(ids)}/{case["expected_events"]} alerts={len(hits)}',flush=True)
    return rows


def write_table(path, rows):
    if not rows:
        return
    cols = sorted({k for row in rows for k in row})
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=cols)
        w.writeheader();w.writerows(rows)


class Live:
    def __init__(self, args, root, out):
        self.a = args; self.root=root; self.out=out
        self.events=root/'data/live-events.jsonl'
        self.alerts=root/'data/live-alerts.jsonl'
        self.kube = ([args.kubectl] if args.kubectl else
                     (['kubectl'] if shutil.which('kubectl') else ['k3s','kubectl']))
        self.svcs=[]; self.pods=[]; self.ips=[]; self.preflight=[]
        self.runid=dt.datetime.now(UTC).strftime('%m%d%H%M%S')
        self.case_commands = {}

    def k(self, *cmd, timeout=120, check=True):
        return run(self.kube+list(cmd),timeout=timeout,check=check)

    def cleanup(self):
        if self.a.keep_resources:
            return
        for pod in self.pods:
            self.k('-n',self.a.namespace,'delete','pod',pod,'--ignore-not-found','--wait=false',check=False,timeout=20)
        for svc in self.svcs:
            self.k('-n',self.a.namespace,'delete','service',svc,'--ignore-not-found','--wait=false',check=False,timeout=20)

    def policy_names(self):
        p=self.k('get','tracingpolicies','-o','json',check=False)
        if p.returncode:
            return set()
        return {x['metadata']['name'] for x in json.loads(p.stdout).get('items',[])}

    def setup(self):
        if not self.events.exists() or not self.alerts.exists():
            raise RuntimeError('live JSONL files not found; start RED-O detector first')
        self.k('get','namespace',self.a.namespace)
        self.pol=self.policy_names()
        self.preflight.append({'policies':sorted(self.pol), 'namespace':self.a.namespace})
        print('Live mode uses only the security-lab namespace; external connections:', self.a.allow_external,flush=True)

    def services(self, n=5):
        if len(self.ips)>=n:
            return self.ips
        for i in range(len(self.ips),n):
            svc=f'redo-all-s{i+1}-{self.runid}'.lower()
            definition = {'apiVersion':'v1','kind':'Service','metadata':{'name':svc,'namespace':self.a.namespace},
                          'spec':{'type':'ClusterIP','ports':[{'name':'test','port':8080,'targetPort':8080}]}}
            tmp=self.out/f'{svc}.json';save(tmp,definition)
            self.k('apply','-f',str(tmp))
            self.svcs.append(svc)
            ip=self.k('-n',self.a.namespace,'get','svc',svc,'-o','jsonpath={.spec.clusterIP}').stdout.strip()
            addr = ipaddress.ip_address(ip)
            rfc1918 = [ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
            if not isinstance(addr, ipaddress.IPv4Address) or not any(addr in subnet for subnet in rfc1918):
                raise RuntimeError('Service IP is not RFC1918 IPv4; cannot test configured R013/R021 CIDRs')
            self.ips.append(ip)
        return self.ips

    def pod(self,rid):
        pod=f'redo-all-{rid.lower()}-{self.runid}'
        self.k('-n',self.a.namespace,'run',pod,'--image',self.a.image,
               '--restart=Never', '--overrides',json.dumps({'spec':{'automountServiceAccountToken':True}}),
               '--command','--','sleep','600',timeout=self.a.timeout)
        self.pods.append(pod)
        self.k('-n',self.a.namespace,'wait','--for=condition=Ready',f'pod/{pod}',f'--timeout={self.a.timeout}s',timeout=self.a.timeout+10)
        return pod

    def exec(self,pod,*cmd,check=False):
        return self.k('-n',self.a.namespace,'exec',pod,'--',*cmd,timeout=45,check=check)

    @staticmethod
    def connect_code():
        return ('import socket,sys; '
                '[(lambda s,ip,port: (s.settimeout(.6),s.connect_ex((ip,int(port))),s.close()))'
                '(socket.socket(),sys.argv[i],sys.argv[i+1]) for i in range(1,len(sys.argv),2)]')

    def connect(self,pod,ip,port):
        return self.exec(pod,'python3','-c',self.connect_code(),ip,str(port))

    def ensure_wget(self,pod):
        """Use a real BusyBox wget applet when Alpine has no /bin/wget link.

        In particular, do NOT mistake a missing executable (OCI exec error) for
        a successful signature detection. Keep preparation inside the test Pod.
        """
        p=self.exec(pod,'/bin/sh','-c',
           'if [ -x /bin/wget ]; then exit 0; fi; '
           'if [ -x /bin/busybox ] && /bin/busybox --list | grep -qx wget; then '
           '  cp /bin/busybox /bin/wget && chmod 755 /bin/wget; '
           'else exit 86; fi')
        if p.returncode:
            return ('No executable /bin/wget and BusyBox wget applet unavailable; '
                    'use a lab image containing /bin/wget')
        return ''

    def action(self,rid,pod):
        # Return (expected event selectors, explicit SKIP reason).
        # A non-zero prerequisite command is an ERROR, never a PASS, except
        # network client exit codes for intentionally unreachable destinations.
        exp=[]
        def sel(kind,**kw):
            return {'event_type':kind, **kw}
        def cmd(*v,allow_failure=False):
            p=self.exec(pod,*v)
            self.case_commands.setdefault(rid,[]).append({
                'argv':list(v), 'exit_code':p.returncode,
                'stderr_tail':(p.stderr or '')[-400:],
                'stdout_tail':(p.stdout or '')[-400:]})
            if p.returncode and not allow_failure:
                raise RuntimeError(
                    f'R{rid[1:]} action exited {p.returncode}: '
                    f'{(p.stderr or p.stdout or "").strip()[-700:]}')
            if p.returncode and allow_failure:
                print(f'INFO {rid}: client exit={p.returncode} is expected for '
                      'unreachable test service (telemetry still checked)',flush=True)
            return p
        external='1.1.1.1'
        if rid == 'R001':
            cmd('/bin/sh','-c','true');exp=[sel('process.exec',binary='/bin/sh')]
        elif rid == 'R002':
            cmd('python3','-c',"open('/etc/shadow','rb').read(1)");exp=[sel('file.access',path='/etc/shadow')]
        elif rid == 'R003':
            cmd('python3','-c',self.connect_code(),external,'443');exp=[sel('network.connect',ip=external)]
        elif rid == 'R004':
            missing=self.ensure_wget(pod)
            if missing: return None,missing
            ip=self.services(1)[0]
            cmd('/bin/wget','-T','2','-O','/dev/null',f'http://{ip}:8080/',allow_failure=True)
            exp=[sel('process.exec',binary='/bin/wget')]
        elif rid == 'R005':
            code="cat /etc/passwd >/dev/null; python3 -c 'import socket; s=socket.socket(); s.settimeout(1); s.connect_ex((\"1.1.1.1\",443)); s.close()'"
            cmd('/bin/sh','-c',code)
            exp=[sel('process.exec',binary='/bin/sh'),sel('file.access',path='/etc/passwd'),sel('network.connect',ip=external)]
        elif rid == 'R006':
            cmd('/bin/sh','-c',"python3 -c 'import socket; s=socket.socket(); s.settimeout(1); s.connect_ex((\"1.1.1.1\",443)); s.close()'")
            exp=[sel('process.exec',binary='/bin/sh'),sel('network.connect',ip=external)]
        elif rid == 'R007':
            # Preserve same python exec ID. A small gap also makes tracing and
            # event-time ordering easier to diagnose, without changing rules.
            code=("import socket,time; "
                  "f=open('/var/run/secrets/kubernetes.io/serviceaccount/token','rb'); "
                  "f.read(1); f.close(); time.sleep(0.35); "
                  "s=socket.socket();s.settimeout(1); "
                  "s.connect_ex(('1.1.1.1',443));s.close()")
            cmd('python3','-c',code)
            exp=[sel('file.access',path_suffix='/token'),sel('network.connect',ip=external)]
        elif rid == 'R008':
            missing=self.ensure_wget(pod)
            if missing: return None,missing
            cmd('/bin/wget','-T','2','-O','/dev/null','http://1.1.1.1:81/',allow_failure=True)
            exp=[sel('process.exec',binary='/bin/wget'),sel('network.connect',ip=external)]
        elif rid == 'R009':
            cmd('/bin/sh','-c','true');exp=[sel('process.exec',binary='/bin/sh')]
        elif rid == 'R010':
            cmd('python3','-c',"open('/var/run/secrets/kubernetes.io/serviceaccount/token','rb').read(1)")
            exp=[sel('file.access',path_suffix='/token')]
        elif rid == 'R011':
            code=('import ctypes,platform; '
                  'n={"x86_64":126,"aarch64":91}.get(platform.machine()); '
                  'assert n is not None; '
                  'H=type("H",(ctypes.Structure,),{"_fields_":[("version",ctypes.c_uint32),("pid",ctypes.c_int)]});'
                  'D=type("D",(ctypes.Structure,),{"_fields_":[("effective",ctypes.c_uint32),("permitted",ctypes.c_uint32),("inheritable",ctypes.c_uint32)]});'
                  'h=H(0x20080522,0);ds=(D*2)();'
                  'r=ctypes.CDLL(None).syscall(n,ctypes.byref(h),ctypes.byref(ds));'
                  'print("capset syscall result",r)')
            cmd('python3','-c',code)
            exp=[sel('kernel.hook',function='security_capset')]
        elif rid in {'R012','R014','R018','R019'}:
            label={'R012':'unshare','R014':'xmrig','R018':'setcap','R019':'nmap'}[rid]
            # A copied Python interpreter is NOT the named real tool. It exits
            # successfully and only tests RED-O's path-name indicator.
            code=('import shutil,sys,os; '
                  f'p="/tmp/{label}"; '
                  'shutil.copyfile(sys.executable,p); os.chmod(p,0o755)')
            cmd('python3','-c',code)
            cmd(f'/tmp/{label}','-c','pass')
            exp=[sel('process.exec',binary=f'/tmp/{label}')]
        elif rid == 'R013':
            ip=self.services(1)[0]
            cmd('python3','-c',self.connect_code(),ip,'8080')
            exp=[sel('network.connect',ip=ip)]
        elif rid == 'R015':
            ip=self.services(1)[0]
            cmd('python3','-c',self.connect_code(),ip,'3333')
            exp=[sel('network.connect',ip=ip,port=3333)]
        elif rid == 'R016':
            exp=[sel('k8s.audit',audit_name=pod)]
        elif rid == 'R017':
            cmd('python3','-c',"import os; p='/run/docker.sock'; assert not os.path.exists(p); open(p,'wb').close();open(p,'rb').read(1)")
            exp=[sel('file.access',path='/run/docker.sock')]
        elif rid == 'R020':
            ip=self.services(1)[0]
            cmd('/bin/sh','-c',f"python3 -c 'import socket;s=socket.socket();s.settimeout(1);s.connect_ex((\"{ip}\",8080));s.close()'")
            exp=[sel('process.exec',binary='/bin/sh'),sel('network.connect',ip=ip)]
        elif rid == 'R021':
            ips=self.services(5)
            args=[]
            for ip in ips:
                args.extend([ip,'8080'])
            cmd('python3','-c',self.connect_code(),*args)
            exp=[sel('network.connect',ip=ip) for ip in ips]
        elif rid == 'R022':
            return None,'requires a separately approved real privilege-raise test; no spoofing'
        else:
            raise ValueError(rid)
        return exp,''

    def is_match(self,event,pattern):
        if event.get('event_type')!=pattern['event_type']:
            return False
        p=event.get('process') or {}; f=event.get('file') or {}; n=event.get('network') or {}; a=event.get('audit') or {}
        return all((p.get('binary')==val if key=='binary' else
                    f.get('path')==val if key=='path' else
                    (f.get('path') or '').endswith(val) if key=='path_suffix' else
                    n.get('destination_ip')==val if key=='ip' else
                    n.get('destination_port')==val if key=='port' else
                    event.get('function')==val if key=='function' else
                    a.get('name')==val if key=='audit_name' else False)
                   for key,val in pattern.items() if key!='event_type')

    @staticmethod
    def _event_debug(e):
        k=e.get('kubernetes') or {}
        p=e.get('process') or {}
        return {
            'event_id':e.get('event_id'),'event_type':e.get('event_type'),
            'timestamp':e.get('timestamp'),'received_at':e.get('received_at'),
            'node':e.get('node'),'pod':k.get('pod'),'pod_uid':k.get('pod_uid'),
            'container_id':k.get('container_id'),'namespace':k.get('namespace'),
            'exec_id':p.get('exec_id'),'parent_exec_id':p.get('parent_exec_id'),
            'binary':p.get('binary'),
            'path':(e.get('file') or {}).get('path'),
            'destination_ip':(e.get('network') or {}).get('destination_ip'),
            'destination_port':(e.get('network') or {}).get('destination_port')}

    def _correlation_preconditions(self,rule,groups,events):
        """Distinguish missing event attributes from a genuine correlator miss."""
        if rule != 'R007' or len(groups)<2 or not groups[0] or not groups[1]:
            return True, ''
        definitions=json.loads((self.root/'configs/correlations.json').read_text(encoding='utf-8'))['correlations']
        ruledef=next(x for x in definitions if x['id']=='R007')
        path_re=re.compile(ruledef['steps'][0]['path_regex'])
        window=dt.timedelta(seconds=ruledef['window_seconds'])
        parents={e.get('process',{}).get('exec_id'):e.get('process',{}).get('parent_exec_id')
                 for e in events if e.get('process',{}).get('exec_id')}
        def ancestor(exec_id,root):
            for _ in range(128):
                if not exec_id or not root:
                    return False
                if exec_id==root:
                    return True
                exec_id=parents.get(exec_id,'')
            return False
        reasons=[]
        for fe in groups[0]:
            for ne in groups[1]:
                f=fe.get('file') or {}
                if not path_re.fullmatch(f.get('path','')):
                    reasons.append('file path does not match R007 path_regex')
                    continue
                fk,nk=fe.get('kubernetes') or {},ne.get('kubernetes') or {}
                if (fk.get('pod_uid'),fk.get('container_id'),fe.get('node')) != \
                   (nk.get('pod_uid'),nk.get('container_id'),ne.get('node')):
                    reasons.append('file/network have different pod_uid, container_id or node')
                    continue
                fexec=(fe.get('process') or {}).get('exec_id')
                nexec=(ne.get('process') or {}).get('exec_id')
                if not ancestor(nexec,fexec):
                    reasons.append('file/network exec_id are neither same nor parent-descendant')
                    continue
                try:
                    a=dt.datetime.fromisoformat(fe['timestamp'].replace('Z','+00:00'))
                    b=dt.datetime.fromisoformat(ne['timestamp'].replace('Z','+00:00'))
                except (KeyError,ValueError,AttributeError):
                    reasons.append('invalid timestamp')
                    continue
                if b<a or b-a>window:
                    reasons.append('events are reversed or more than 45s apart')
                    continue
                return True,''
        return False,'; '.join(sorted(set(reasons))) or 'no valid R007 event pair'

    def scan_case(self,pod,rule,expected):
        # Only active JSONL, fresh Pod names, exact source-event attribution.
        events=[e for e in jsonlines(self.events) if (e.get('kubernetes') or {}).get('pod')==pod]
        byid={e.get('event_id'):e for e in events if e.get('event_id')}
        eventids=set(byid)
        matched_groups=[[e for e in events if self.is_match(e,x)] for x in expected]
        counts=[len(g) for g in matched_groups]
        telemetry=all(n>0 for n in counts)
        raw_alerts=[a for a in jsonlines(self.alerts)
                    if a.get('rule_id')==rule and
                    (a.get('kubernetes') or {}).get('pod')==pod and
                    bool(a.get('related_event_ids')) and
                    set(a.get('related_event_ids')).issubset(eventids)]
        minchain={'R005':3,'R006':2,'R007':2,'R008':2,'R020':2,'R021':5}.get(rule,1)
        # Require each expected action event to appear in a linked target alert,
        # not merely some other event from the same Pod.
        alerts=[]
        for a in raw_alerts:
            linked=set(a['related_event_ids'])
            if len(linked)<minchain:
                continue
            if not all(any(e.get('event_id') in linked for e in group)
                       for group in matched_groups):
                continue
            alerts.append(a)
        chain=max([len(a.get('related_event_ids') or []) for a in alerts],default=0)
        precond,precond_reason=self._correlation_preconditions(rule,matched_groups,events)
        status=('PASS' if telemetry and chain>=minchain else
                'FAIL_TELEMETRY' if not telemetry else
                'FAIL_PRECONDITION' if not precond else 'FAIL_RULE')
        first_emitted=min((a.get('emitted_at') for a in alerts if a.get('emitted_at')), default=None)
        # A compact, non-secret snapshot makes R007 failure diagnosable on VM.
        diagnostic={'rule':rule,'pod':pod,'status':status,'precondition_ok':precond,
            'precondition_reason':precond_reason,
            'matched_patterns':expected,'match_counts':counts,
            'matched_events':[[self._event_debug(e) for e in g[:15]] for g in matched_groups],
            'raw_target_alerts':[{'rule_id':a.get('rule_id'),
              'related_event_ids':a.get('related_event_ids')} for a in raw_alerts]}
        save(self.out/f'diagnostic-{rule}.json',diagnostic)
        return {'rule_id':rule,'status':status,'pod':pod,'telemetry':telemetry,
                'matched_expectations':counts,'first_alert_emitted_at':first_emitted,
                'matched_alerts':len(alerts),'max_related_ids':chain,
                'event_ids':sorted(set().union(*[{e.get('event_id') for e in group}
                                                 for group in matched_groups])),
                'precondition_ok':precond,'precondition_reason':precond_reason,
                'diagnostic_file':f'diagnostic-{rule}.json',
                'details':'Live positive indicator smoke only; no attack or exploit established'}

    def execute(self):
        self.setup(); rows=[]
        save(self.out/'preflight.json',self.preflight)
        save(self.out/'trial-plan.json',{'created_at':utcnow(),'namespace':self.a.namespace,
            'planned_rules':self.a.selected_rules,'labels':'positive indicator checks only',
            'warning':'These are authorized lab actions, not attacks or positive evidence of compromise'})
        for rid in self.a.selected_rules:
            skip=''
            if rid in {'R003','R005','R006','R007','R008'} and not self.a.allow_external:
                skip='outbound to 1.1.1.1 disabled; use --allow-external'
            elif rid=='R011' and 'red-o-privilege-capset' not in self.pol:
                skip='TracingPolicy red-o-privilege-capset is not installed'
            elif rid=='R017' and 'red-o-runtime-sockets' not in self.pol:
                skip='TracingPolicy red-o-runtime-sockets is not installed'
            elif rid in {'R003','R005','R006','R007','R008','R013','R015','R020','R021'} and 'lab-network-connect' not in self.pol:
                skip='TracingPolicy lab-network-connect is not installed'
            elif rid=='R005' and 'lab-file-access' not in self.pol:
                skip='TracingPolicy lab-file-access is not installed'
            elif rid=='R002' and 'lab-file-access' not in self.pol:
                skip='TracingPolicy lab-file-access is not installed'
            elif rid=='R010' and 'red-o-serviceaccount-token' not in self.pol:
                skip='TracingPolicy red-o-serviceaccount-token is not installed'
            elif rid=='R022':
                skip='needs a separate real privilege raise test (not simulated)'
            elif rid=='R016' and not any(x.get('type')=='audit' for x in json.loads((self.root/'configs/sensors.json').read_text())['sensors']):
                skip='no Kubernetes Audit sensor in configs/sensors.json'
            if skip:
                row={'rule_id':rid,'status':'SKIP','reason':skip}
                rows.append(row); print(f'SKIP  live {rid}: {skip}',flush=True);continue
            try:
                pod=self.pod(rid)
                started_at=utcnow()
                expected, reason=self.action(rid,pod)
                finished_at=utcnow()
                if expected is None:
                    row={'rule_id':rid,'status':'SKIP','reason':reason}
                else:
                    # Wait long enough for global multi-source watermark / idle flush.
                    end=time.monotonic()+self.a.wait_seconds
                    row=self.scan_case(pod,rid,expected)
                    while row['status'] not in ('PASS','FAIL_PRECONDITION') and time.monotonic()<end:
                        time.sleep(1)
                        row=self.scan_case(pod,rid,expected)
                    row['expected_event_patterns']=expected
                    row['action_commands']=self.case_commands.get(rid,[])
                    row['action_started_at']=started_at
                    row['action_finished_at']=finished_at
                    try:
                        emitted=row.get('first_alert_emitted_at')
                        if emitted:
                            start=dt.datetime.fromisoformat(started_at.replace('Z','+00:00'))
                            end=dt.datetime.fromisoformat(emitted.replace('Z','+00:00'))
                            row['action_to_alert_ms']=round((end-start).total_seconds()*1000,3)
                    except (ValueError,TypeError):
                        pass
                rows.append(row)
                print(f'{row["status"]:15} live {rid}   alert={row.get("matched_alerts",0)}  source={pod}',flush=True)
            except Exception as exc:
                row={'rule_id':rid,'status':'ERROR','reason':str(exc)}
                rows.append(row)
                print(f'ERROR live {rid}: {exc}',flush=True)
            finally:
                # Remove Pod immediately rather than retaining ~20 Pods on a small K3s VM.
                if not self.a.keep_resources and self.pods:
                    pod=self.pods.pop()
                    self.k('-n',self.a.namespace,'delete','pod',pod,'--ignore-not-found','--wait=false',check=False,timeout=20)
        write_table(self.out/'summary.csv',rows)
        save(self.out/'summary.json',{'mode':'live','rows':rows,'caveats':['Only selected safe live indicators attempted.',
             'R012/R014/R018/R019 use working benign Python executable copies named after tools; not actual tools or attacks.',
             'Missing/disabled policy or inability to capture kernel event is not automatically a rule engine bug.',
             'No negative-control Precision/Recall calculated from this smoke run.']})
        return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--project',default='.',help='RED-O root with bin/red-o and configs/')
    ap.add_argument('--mode',choices=['replay','live','both'],default='replay')
    ap.add_argument('--output',help='output directory (defaults to benchmark-results/all-rules-<UTC>)')
    ap.add_argument('--execute',action='store_true',help='REQUIRED for live mode to create laboratory Pods/Services')
    ap.add_argument('--allow-external',action='store_true',help='explicitly allow TCP probes to 1.1.1.1 in live mode')
    ap.add_argument('--kubectl',help='kubectl binary path; otherwise auto-select kubectl or k3s kubectl')
    ap.add_argument('--namespace',default='security-lab',help='must be security-lab for default detection rules')
    ap.add_argument('--image',default='python:3.12-alpine',help='test image, should have Python 3 and /bin/sh')
    ap.add_argument('--timeout',type=int,default=120)
    ap.add_argument('--wait-seconds',type=int,default=10)
    ap.add_argument('--keep-resources',action='store_true',help='keep temporary live resources for inspection')
    ap.add_argument('--only',help='comma-separated rule IDs for live mode, e.g. R005,R021; default all 22')
    args=ap.parse_args()
    root=Path(args.project).resolve()
    binary=root/'bin/red-o'
    if not binary.is_file() or not os.access(binary,os.X_OK):
        ap.error(f'{binary} is not executable; first run go build -o bin/red-o ./cmd/red-o')
    read_rules(root)
    args.selected_rules = ALL if not args.only else [x.strip().upper() for x in args.only.split(',')]
    if not args.selected_rules or len(set(args.selected_rules)) != len(args.selected_rules) or any(x not in ALL for x in args.selected_rules):
        ap.error('--only must contain unique rule IDs R001..R022')
    if args.only and args.mode=='replay':
        ap.error('--only is for live mode; replay always validates all 22 rules')
    if args.namespace!='security-lab':
        ap.error('default detection rules restrict tests to namespace security-lab')
    out=Path(args.output).resolve() if args.output else root/'benchmark-results'/f'all-rules-{stamp()}'
    if out.exists():
        ap.error(f'output exists, refusing to overwrite: {out}')
    if args.mode in ('live','both') and not args.execute:
        ap.error('live mode changes the cluster: add --execute after reviewing the script')
    out.mkdir(parents=True)
    meta={'tool':'tools/check_rules.py','mode':args.mode,'created_at':utcnow(),
          'rules':ALL,'project':str(root),'build_version':(root/'VERSION').read_text(encoding='utf-8').strip(),
          'warnings':['Replay is synthetic; it verifies matching/normalization/correlation, not live K3s detection.',
                      'Live tests are safe indicators only; no actual container escape, cryptomining, or privilege escalation.',
                      'No ClickHouse or RED-O data files are modified; live Pods/Services are temporary.']}
    save(out/'metadata.json',meta)
    failed=False
    if args.mode in ('replay','both'):
        dest=out/'replay';dest.mkdir()
        rows=make_replay(root,dest)
        write_table(dest/'summary.csv',rows)
        save(dest/'summary.json',{'mode':'replay','rows':rows, 'pass':sum(x['status']=='PASS' for x in rows),
                                  'total':len(rows),'all_pass':all(x['status']=='PASS' for x in rows)})
        failed |= any(x['status']!='PASS' for x in rows)
        print(f'Replay PASS {sum(x["status"]=="PASS" for x in rows)}/{len(rows)} trials',flush=True)
    if args.mode in ('live','both'):
        dest=out/'live';dest.mkdir()
        runner=Live(args,root,dest)
        try:
            rows=runner.execute()
        finally:
            runner.cleanup()
        n={s:sum(x['status']==s for x in rows) for s in ['PASS','SKIP','FAIL_RULE','FAIL_PRECONDITION','FAIL_TELEMETRY','ERROR']}
        print('Live:',n,flush=True)
        failed |= any(x['status'] in ('FAIL_RULE','FAIL_PRECONDITION','FAIL_TELEMETRY','ERROR') for x in rows)
    print('Reports:',out,flush=True)
    return 1 if failed else 0


if __name__=='__main__':
    sys.exit(main())
