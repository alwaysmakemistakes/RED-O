#!/usr/bin/env python3
"""RED-O v0.9.6 opt-in, non-shell live experiment orchestrator.

This is NOT an attack generator and does NOT invent event IDs. The user authors
all labels, lab-only command arrays and strong event selectors in advance.
The resulting v1.1 manifest is consumable by `red-o benchmark quality evaluate`.
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import uuid

SCENARIOS = frozenset(('commands', 'credentials', 'privilege', 'escape', 'network', 'resources', 'workload'))
REQUIRED_SELECTOR = frozenset(('audit.name', 'process.arguments_contains', 'file.path_regex',
                               'network.destination_ip', 'process.binary_regex', 'process.binary'))


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def parse_timestamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def field(obj, dotted):
    value = obj
    for key in dotted.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def validate_trial(trial):
    if trial.get('scenario') not in SCENARIOS:
        raise ValueError(f"trial {trial.get('id')}: unrecognized scenario")
    if trial.get('label') not in ('positive', 'negative'):
        raise ValueError(f"trial {trial.get('id')}: label must be assigned before execution")
    if not trial.get('id') or not isinstance(trial.get('command'), list) or not trial['command']:
        raise ValueError('each trial requires id and command argv array')
    if not all(isinstance(x, str) and x for x in trial['command']):
        raise ValueError(f"trial {trial['id']}: invalid command array")
    selector = trial.get('selector')
    if not isinstance(selector, dict) or not selector.get('event_type'):
        raise ValueError(f"trial {trial['id']}: selector requires event_type")
    if not (REQUIRED_SELECTOR & selector.keys()):
        raise ValueError(f"trial {trial['id']}: selector must identify a specific action, not merely a Pod/time")
    expected = trial.get('expected_events', 1)
    if not isinstance(expected, int) or not 1 <= expected <= 10000:
        raise ValueError(f"trial {trial['id']}: expected_events must be 1..10000")
    if not isinstance(trial.get('enabled', False), bool):
        raise ValueError('enabled must be explicit boolean')


def all_records(spec):
    files = []
    for part in spec.split(','):
        matches = sorted(glob.glob(part.strip()))
        if not matches:
            raise FileNotFoundError(f"no event files for {part}")
        files.extend(matches)
    for path in dict.fromkeys(files):
        with open(path, 'r', encoding='utf-8') as f:
            for ln, raw in enumerate(f, 1):
                if raw.strip():
                    try:
                        yield json.loads(raw)
                    except json.JSONDecodeError as e:
                        raise ValueError(f"bad JSONL {path}:{ln}: {e}") from e


def matches(record, selector):
    import re
    for key, required in selector.items():
        if key.endswith('_contains'):
            actual = field(record, key[:-len('_contains')])
            if not isinstance(actual, str) or required not in actual:
                return False
        elif key.endswith('_regex'):
            actual = field(record, key[:-len('_regex')])
            if not isinstance(actual, str) or not re.search(required, actual):
                return False
        else:
            actual = field(record, key)
            if isinstance(required, list):
                if actual not in required:
                    return False
            elif actual != required:
                return False
    return True


def render(v, run_id):
    if isinstance(v, str):
        return v.replace('{{RUN_ID}}', run_id)
    if isinstance(v, list):
        return [render(x, run_id) for x in v]
    if isinstance(v, dict):
        return {k: render(x, run_id) for k, x in v.items()}
    return v


def select_evidence(records, trial, slack_seconds):
    start = parse_timestamp(trial['action_started_at']) - dt.timedelta(seconds=slack_seconds)
    end = parse_timestamp(trial['action_finished_at']) + dt.timedelta(seconds=slack_seconds)
    selected = []
    for event in records:
        if not matches(event, trial['selector']):
            continue
        stamp = event.get('timestamp')
        if not stamp:
            continue
        try:
            when = parse_timestamp(stamp)
        except ValueError:
            continue
        if start <= when <= end and event.get('event_id'):
            selected.append(event['event_id'])
    return sorted(set(selected))


def run(plan_file, output, event_files, execute, settle, slack, timeout, red_o, alerts, suite):
    plan = json.loads(pathlib.Path(plan_file).read_text(encoding='utf-8'))
    if plan.get('schema_version') != '1.0' or not isinstance(plan.get('trials'), list):
        raise ValueError('plan schema_version 1.0 and trials list required')
    used = set()
    for item in plan['trials']:
        validate_trial(item)
        if item['id'] in used:
            raise ValueError(f"duplicate trial {item['id']}")
        used.add(item['id'])
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    configured = [render(v, run_id) for v in plan['trials'] if v.get('enabled')]
    print(f"Plan: {len(plan['trials'])} defined, {len(configured)} enabled; mode={'EXECUTE' if execute else 'DRY-RUN'}")
    for v in configured:
        print(f"  {v['id']} [{v['scenario']}:{v['label']}] argv={v['command']!r} selector={v['selector']!r}")
    if not execute:
        print('No commands executed. Review the plan, then pass --execute on your own test VM.')
        return 0
    if not configured:
        raise ValueError('no enabled trials: refusing to generate an empty or misleading report')
    out = pathlib.Path(output)
    out.mkdir(parents=True, exist_ok=False)
    receipts = []
    trials = []
    for item in configured:
        command = item['command']
        started = utcnow()
        try:
            proc = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=timeout, shell=False, check=False)
            code, state = proc.returncode, 'completed' if proc.returncode == 0 else 'failed'
        except (OSError, subprocess.TimeoutExpired):
            code, state = None, 'failed'
        finished = utcnow()
        receipt = {'trial_id': item['id'], 'scenario': item['scenario'], 'label': item['label'],
                   'action_id': str(uuid.uuid4()), 'action_status': state,
                   'action_started_at': started, 'action_finished_at': finished,
                   'exit_code': code,
                   'command_sha256': hashlib.sha256(json.dumps(command).encode()).hexdigest(),
                   'selector': item['selector'], 'expected_events': item.get('expected_events', 1)}
        receipts.append(receipt)
        print(f"  {item['id']}: {state} rc={code}")
        if state == 'completed':
            trials.append((item, receipt))
    time.sleep(settle)
    records = list(all_records(event_files))
    owners = {}
    manifest = {'schema_version': '1.1', 'trials': []}
    for item, receipt in trials:
        ids = select_evidence(records, {**item, **receipt}, slack)
        for event_id in ids:
            if event_id in owners:
                raise ValueError(f"event_id {event_id} selected by both {owners[event_id]} and {item['id']}; tighten selectors")
            owners[event_id] = item['id']
        manifest['trials'].append({k: receipt[k] for k in (
            'action_id', 'action_status', 'action_started_at', 'action_finished_at', 'expected_events')}
            | {'id': item['id'], 'scenario': item['scenario'], 'label': item['label'], 'event_ids': ids})
        print(f"  {item['id']}: captured {len(ids)}/{receipt['expected_events']} expected event(s)")
    (out / 'actions.json').write_text(json.dumps(receipts, indent=2) + '\n', encoding='utf-8')
    (out / 'trials.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (out / 'plan-snapshot.json').write_text(json.dumps(configured, indent=2) + '\n', encoding='utf-8')
    if not manifest['trials']:
        print('All actions failed; no evaluation generated. Inspect actions.json.', file=sys.stderr)
        return 1
    if red_o:
        if not alerts:
            raise ValueError('provide --alerts when using --red-o')
        command = [red_o, 'benchmark', 'quality', 'evaluate', '-manifest', str(out / 'trials.json'),
                   '-events', event_files, '-alerts', alerts, '-output', str(out / 'evaluation'),
                   '-suite', suite, '-strict-attribution=true']
        proc = subprocess.run(command, check=False)
        return proc.returncode
    print(f"Manifest: {out / 'trials.json'}. Evaluate with red-o benchmark quality evaluate.")
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, help='reviewed lab-only JSON plan; all labels assigned before execution')
    parser.add_argument('--events', required=True, help='normalized event JSONL paths/globs, comma-separated')
    parser.add_argument('--output', required=True, help='new, empty output directory')
    parser.add_argument('--execute', action='store_true', help='REQUIRED to execute user-supplied command arrays')
    parser.add_argument('--settle', type=float, default=8.0, help='seconds to allow event collection after actions')
    parser.add_argument('--clock-slack', type=float, default=2.0, help='UTC timestamp collection tolerance before and after action')
    parser.add_argument('--timeout', type=float, default=120.0, help='per-action timeout in seconds')
    parser.add_argument('--red-o', help='optional built v0.9.6 CLI to run evaluation automatically')
    parser.add_argument('--alerts', help='alert JSONL inputs (required with --red-o)')
    parser.add_argument('--suite', default='tests/fixtures/detection-quality/scenarios.json')
    args=parser.parse_args()
    if args.settle<0 or args.clock_slack<0 or args.clock_slack>120 or args.timeout<=0:
        parser.error('invalid settle/clock-slack/timeout')
    try:
        return run(args.plan,args.output,args.events,args.execute,args.settle,args.clock_slack,
                   args.timeout,args.red_o,args.alerts,args.suite)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f'quality runner: {e}', file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
