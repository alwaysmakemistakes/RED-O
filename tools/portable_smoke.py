#!/usr/bin/env python3
"""Offline first-install exercise: mock Kubernetes/Tetragon, no ClickHouse or root."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def run(binary, args, folder, env, timeout=25):
    return subprocess.run([str(binary), *args], cwd=folder, env=env,
                          text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--project', type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument('--binary', type=Path, default=Path('bin/red-o'))
    a = p.parse_args()
    project = a.project.resolve()
    binary = (project / a.binary).resolve() if not a.binary.is_absolute() else a.binary
    if not binary.is_file():
        raise SystemExit(f'Missing binary: {binary}')
    with tempfile.TemporaryDirectory(prefix='redo-portable-smoke-') as d:
        folder = Path(d) / 'RED-O'
        (folder / 'configs').mkdir(parents=True)
        (folder / 'bin').mkdir()
        shutil.copyfile(binary, folder / 'bin/red-o')
        (folder / 'bin/red-o').chmod(0o755)
        for name in ('rules.json', 'correlations.json'):
            shutil.copyfile(project / 'configs' / name, folder / 'configs' / name)
        mock = Path(d) / 'fakebin'
        mock.mkdir()
        kubectl = mock / 'kubectl'
        kubectl.write_text('''#!/bin/sh
case "$*" in
  'config current-context') echo test-context ;;
  'get pods --all-namespaces -o json') cat <<'JSON'
{"items":[{"metadata":{"name":"tetragon-1","namespace":"kube-system"},"spec":{"nodeName":"node-one","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}},{"metadata":{"name":"tetragon-operator","namespace":"kube-system"},"spec":{"nodeName":"node-one","containers":[{"name":"operator"}]},"status":{"phase":"Running"}}]}
JSON
    ;;
  *'exec pod/tetragon-1 -c tetragon -- tetra getevents -o json'*) exec sleep 30 ;;
  *) echo "Unexpected mock kubectl: $*" >&2; exit 1 ;;
esac
''')
        kubectl.chmod(0o755)
        env = os.environ.copy()
        env['PATH'] = f'{mock}:{env.get("PATH", "")}'
        env.pop('WEB_PASSWORD', None)
        env.pop('WEB_USER', None)
        env.pop('CH_PASSWORD', None)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        b = folder / 'bin/red-o'
        started = False
        try:
            response = run(b, ['up', '-storage', 'jsonl', '-web-listen', f'127.0.0.1:{port}'], folder, env)
            if response.returncode != 0:
                raise RuntimeError(f'portable up failed: {response.stdout}')
            started = True
            config = json.loads((folder / 'configs/sensors.json').read_text())
            if len(config['sensors']) != 1 or config['sensors'][0]['pod'] != 'tetragon-1':
                raise RuntimeError(f'invalid auto discovery: {config}')
            secrets = folder / '.env'
            if secrets.stat().st_mode & 0o077:
                raise RuntimeError('private .env is readable by group/others')
            pwd = next(x.split('=', 1)[1] for x in secrets.read_text().splitlines()
                       if x.startswith('WEB_PASSWORD='))
            if pwd in ('admin', 'change-me', ''):
                raise RuntimeError('initial Web password is not unique')
            event_file = folder / 'data/live-events.jsonl'
            event_file.write_text(json.dumps({'event_id': 'portable-e1', 'event_type': 'process.exec',
                                              'timestamp': '2026-11-21T18:00:00Z',
                                              'kubernetes': {'namespace': 'security-lab'}}) + '\n')
            url = f'http://127.0.0.1:{port}/api/events'
            def get(auth=False):
                req = urllib.request.Request(url)
                if auth:
                    raw = base64.b64encode(f'admin:{pwd}'.encode()).decode()
                    req.add_header('Authorization', f'Basic {raw}')
                return urllib.request.urlopen(req, timeout=3)
            for _ in range(30):
                try:
                    with get(False) as noauth:
                        raise RuntimeError('Web unexpectedly allowed unauthenticated request')
                except urllib.error.HTTPError as e:
                    if e.code == 401:
                        break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Web was not reachable')
            with get(True) as ok:
                if ok.status != 200 or 'portable-e1' not in ok.read().decode():
                    raise RuntimeError('JSONL Web not serving recorded event')
            print('PASS portable setup: one Ready Tetragon Pod, no local Audit/ClickHouse, private credentials, Web 401/200 and JSONL data')
        finally:
            if started:
                stopped = run(b, ['down'], folder, env, timeout=22)
                if stopped.returncode != 0:
                    raise RuntimeError(f'portable down failed: {stopped.stdout}')


if __name__ == '__main__':
    main()
