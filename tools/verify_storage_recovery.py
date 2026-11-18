#!/usr/bin/env python3
"""Capture an isolated K3s JSONL outage delta and verify exact event IDs in ClickHouse.

Usage:
  python3 tools/verify_storage_recovery.py capture --label before
  # stop ClickHouse, generate events, leave ClickHouse DOWN
  python3 tools/verify_storage_recovery.py capture --label outage
  # restart ClickHouse and wait for checkpoint catch-up
  python3 tools/verify_storage_recovery.py verify

Copies only event IDs, not tokens or payloads. Works on active + queued segments;
run from the repository root. All snapshots persist in the chosen report dir.
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


def snapshot(data_path: Path):
    files = sorted(data_path.parent.glob(data_path.name + '.segment-*')) + [data_path]
    ids = []
    for file in files:
        if not file.is_file():
            continue
        with file.open('rb') as f:
            for line in f:
                if not line.endswith(b'\n'):
                    break
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise RuntimeError(f'invalid JSONL in {file}: {exc}') from exc
                eid = event.get('event_id')
                if eid:
                    ids.append(eid)
    return ids


def sql_rows(container):
    # Credentials are supplied by the container environment, not echoed.
    cmd = ['docker', 'exec', container, 'sh', '-c',
           'clickhouse-client --user "${CLICKHOUSE_USER:-default}" '
           '--password "${CLICKHOUSE_PASSWORD:-}" '
           '--query "SELECT event_id, count() FROM runtime_security.events GROUP BY event_id FORMAT TSV"']
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    counts = {}
    for line in result.stdout.splitlines():
        eid, count = line.split('\t', 1)
        counts[eid] = int(count)
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('action', choices=['capture', 'verify'])
    ap.add_argument('--label', choices=['before', 'outage'])
    ap.add_argument('--events', default='data/live-events.jsonl')
    ap.add_argument('--report-dir', default='benchmark-results/storage-recovery')
    ap.add_argument('--container', default='clickhouse-clickhouse-1')
    args = ap.parse_args()
    report = Path(args.report_dir)
    report.mkdir(parents=True, exist_ok=True)
    if args.action == 'capture':
        if not args.label:
            ap.error('--label is required for capture')
        ids = snapshot(Path(args.events))
        p = report / f'{args.label}-ids.json'
        p.write_text(json.dumps(ids, indent=2) + '\n')
        print(f'{args.label}: {len(ids)} JSONL event IDs saved to {p}')
        return 0
    try:
        before = set(json.loads((report / 'before-ids.json').read_text()))
        during = json.loads((report / 'outage-ids.json').read_text())
        delta = Counter(during) - Counter({eid: 1 for eid in before})
        wanted = set(delta)
        if not wanted:
            raise RuntimeError('no new event IDs in outage capture; test is inconclusive')
        db_counts = sql_rows(args.container)
        missing = sorted(eid for eid in wanted if eid not in db_counts)
        duplicated_db = sorted(eid for eid in wanted if db_counts.get(eid, 0) > 1)
        duplicated_jsonl = sorted(eid for eid in wanted if delta[eid] > 1)
        result = {'outage_unique_ids': len(wanted), 'outage_total_rows': sum(delta.values()),
                  'missing_in_clickhouse': len(missing), 'duplicate_ids_in_clickhouse': len(duplicated_db),
                  'duplicate_ids_in_jsonl': len(duplicated_jsonl), 'pass': not (missing or duplicated_db or duplicated_jsonl),
                  'note': 'Counts describe physical rows at query time; ReplacingMergeTree merges may occur asynchronously.'}
        (report / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        return 0 if result['pass'] else 1
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f'verification failed or inconclusive: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
