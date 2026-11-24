#!/usr/bin/env python3
"""RED-O offline release qualification (no cluster or ClickHouse access).

Runs the same checks before publishing and on the VM. Reports are immutable
per invocation. This is an integration smoke test, NOT live threat detection
validation or proof of a production-ready system.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

EXPECTED_BASELINE = {'tp': 14, 'fp': 7, 'fn': 7, 'tn': 7}
EXPECTED_COMPARE_BASELINE = {'tp': 1, 'fp': 1, 'fn': 0, 'tn': 0}
EXPECTED_COMPARE_CONTEXT = {'tp': 1, 'fp': 0, 'fn': 0, 'tn': 1}


def assert_counts(report, expected):
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f'{key} expected {value}, got {report.get(key)}')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda: f.read(128 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def run_release_smoke(project, output, skip_watermark=False, skip_go_tests=False):
    project = Path(project).resolve()
    output = Path(output).resolve()
    if output.exists():
        raise ValueError(f'refusing to overwrite existing results: {output}')
    if not (project / 'configs' / 'rules.json').is_file():
        raise ValueError('project must contain configs/rules.json')
    output.mkdir(parents=True)
    records = []
    binary = str(project / 'bin' / 'red-o')

    def step(name, command, verify=None, timeout=180):
        logfile = output / f'{len(records) + 1:02d}-{name}.log'
        start = time.monotonic()
        rc = None
        problem = None
        try:
            completed = subprocess.run(command, cwd=project,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, timeout=timeout, check=False)
            rc = completed.returncode
            logfile.write_text(completed.stdout, encoding='utf-8')
            if rc != 0:
                problem = f'exit code {rc}'
            elif verify is not None:
                verify()
        except (Exception) as e:
            problem = str(e)
            if not logfile.exists():
                logfile.write_text(f'Error: {e}\n', encoding='utf-8')
        result = {'name': name, 'pass': problem is None, 'elapsed_seconds': round(time.monotonic()-start, 3),
                  'exit_code': rc, 'command': command, 'log': logfile.name}
        if problem:
            result['error'] = problem
        records.append(result)
        print(f"{'PASS' if problem is None else 'FAIL'}  {name} ({result['elapsed_seconds']}s)", flush=True)
        return problem is None

    def finish():
        report = {
            'schema_version': '1.0', 'release': (project / 'VERSION').read_text().strip(),
            'kind': 'offline-release-smoke',
            'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'project': str(project), 'all_pass': all(x['pass'] for x in records),
            'steps': records,
            'inputs_sha256': {f: sha256(project / f) for f in (
                'VERSION', 'RELEASE.json', 'configs/rules.json', 'configs/correlations.json',
                'tests/fixtures/detection-quality/scenarios.json',
                'deployments/tracing-policies/serviceaccount-token.yaml')},
            'caveats': [
                'Synthetic 35-case baseline has a deliberately balanced error profile; it is not field precision.',
                'Context comparison demo is constructed and does not establish production FP reduction.',
                'FIFO watermark lab exercises controlled JSONL inputs, not live kernel eBPF delivery.',
                'No real Kubernetes cluster or ClickHouse is contacted: portable startup uses a mock kubectl.',
                'Live seven-scenario detection and coverage must be remeasured on the target VM.'
            ]
        }
        (output / 'smoke.json').write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
        print(f'All PASS: {report["all_pass"]} | report: {output / "smoke.json"}', flush=True)
        return 0 if report['all_pass'] else 1

    if not skip_go_tests:
        if not step('go-test', ['go', 'test', '-count=1', './...']):
            return finish()
        if not step('go-vet', ['go', 'vet', './...']):
            return finish()
    if not step('build', ['go', 'build', '-o', binary, './cmd/red-o']):
        return finish()
    if not step('version', [binary, 'version', '-json'],
                lambda: check_release_version(binary, project)):
        return finish()
    if not step('doctor-offline', [binary, 'doctor', '-json'],
                lambda: check_doctor(binary, project)):
        return finish()
    if not step('python-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tools', '-p', 'test_*.py']):
        return finish()

    baseline = output / 'quality-baseline'
    if not step('quality-synthetic', [binary, 'benchmark', 'quality', 'run', '-runs', '1', '-output', str(baseline)],
                lambda: assert_counts(read_json(baseline / 'quality.json'), EXPECTED_BASELINE)):
        return finish()
    compare = output / 'context-demo'
    if not step('context-demo', [binary, 'benchmark', 'quality', 'compare',
                                '-context-policy', 'tests/fixtures/context-demo/policy.json',
                                '-manifest', 'tests/fixtures/context-demo/manifest.json',
                                '-events', 'tests/fixtures/context-demo/events.jsonl',
                                '-alerts', 'tests/fixtures/context-demo/alerts.jsonl',
                                '-output', str(compare)],
                lambda: check_comparison(compare)):
        return finish()
    if not skip_watermark:
        watermark = output / 'watermark'
        if not step('watermark', [sys.executable, 'tools/watermark_experiment.py', '--project', str(project), '--output', str(watermark)],
                    lambda: check_watermark(watermark), timeout=100):
            return finish()
    if not step('portable-offline', [sys.executable, 'tools/portable_smoke.py', '--project', str(project), '--binary', 'bin/red-o'], timeout=50):
        return finish()
    rule_replay = output / 'all-rules-replay'
    if not step('all-rules-replay', [sys.executable, 'tools/check_rules.py', '--project', str(project), '--mode', 'replay', '--output', str(rule_replay)],
                lambda: check_rule_replay(rule_replay), timeout=150):
        return finish()
    return finish()


def check_rule_replay(folder):
    result = read_json(folder / 'replay' / 'summary.json')
    if not result['all_pass'] or result['pass'] != 44 or result['total'] != 44:
        raise ValueError('all-rules replay did not pass 44/44')


def check_release_version(binary, project):
    expected = (project / 'VERSION').read_text().strip()
    if read_json(project / 'RELEASE.json')['version'] != expected:
        raise ValueError('release metadata mismatch')
    v = json.loads(subprocess.check_output([binary, 'version', '-json'], text=True))
    if v.get('version') != expected:
        raise ValueError('binary VERSION mismatch')


def check_doctor(binary, project):
    out = json.loads(subprocess.check_output([binary, 'doctor', '-json'], cwd=project, text=True))
    if not out['ready'] or out['failed'] != 0:
        raise ValueError(f'local preflight failed: {out}')
    names = {x['name']: x for x in out['checks']}
    for name in ('rules', 'correlations', 'seven-scenario-suite', 'serviceaccount-tracingpolicy'):
        if names.get(name, {}).get('status') != 'pass':
            raise ValueError(f'{name} not PASS')


def check_comparison(folder):
    result = read_json(folder / 'comparison.json')
    assert_counts(result['baseline'], EXPECTED_COMPARE_BASELINE)
    assert_counts(result['contextual'], EXPECTED_COMPARE_CONTEXT)
    if result['approved'] != 1:
        raise ValueError('context demo approval count differs from baseline')


def check_watermark(folder):
    result = read_json(folder / 'summary.json')
    if not result['all_pass'] or len(result['results']) != 4:
        raise ValueError('watermark tests did not all pass')
    if not all(x['pass'] for x in result['results']):
        raise ValueError('at least one watermark case failed')
    for case in result['results']:
        alerts_file = folder / case['case'] / 'alerts.jsonl'
        if case['case'] == 'A_reorder' and not any('"detected_at"' in line and '"emitted_at"' in line
                                                  for line in alerts_file.read_text().splitlines()):
            raise ValueError('new-format forensic alert timing fields missing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', default='.', help='source checkout containing VERSION and configs/')
    parser.add_argument('--output', default='', help='new empty output path (will not overwrite)')
    parser.add_argument('--skip-watermark', action='store_true', help='quick offline smoke without 4 FIFO tests')
    parser.add_argument('--skip-go-tests', action='store_true', help='only useful if Go tests/vet ran separately')
    args = parser.parse_args()
    project = Path(args.project).resolve()
    output = Path(args.output).resolve() if args.output else project / 'benchmark-results' / (
        'smoke-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    try:
        return run_release_smoke(project, output, args.skip_watermark, args.skip_go_tests)
    except (OSError, ValueError) as e:
        parser.error(str(e))


if __name__ == '__main__':
    sys.exit(main())
