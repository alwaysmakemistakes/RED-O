#!/usr/bin/env python3
"""RED-O v0.9.0 opt-in K3s performance harness (Python stdlib only).

Never claims kernel-to-alert latency or lossless Tetragon capture. Workload
runs only inside an explicitly selected, already-running laboratory Pod.
"""
import argparse
import csv
import datetime as dt
import functools
import json
import math
import os
import platform
from pathlib import Path
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

METRIC = re.compile(r'^(redo_[a-zA-Z0-9_]+)(?:\{[^}]*\})?\s+([-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)$')


def quantile(values, percentage):
    """Linear interpolation between sorted samples; returns None if empty."""
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentage / 100.0
    low, high = math.floor(index), math.ceil(index)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def describe(values):
    return {'count': len(values), 'min': min(values) if values else None,
            'mean': statistics.mean(values) if values else None,
            'max': max(values) if values else None,
            'p50': quantile(values, 50), 'p95': quantile(values, 95),
            'p99': quantile(values, 99)}


def parse_prometheus(body):
    out = {}
    for line in body.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        match = METRIC.match(line)
        if match and '{' not in line:
            out[match.group(1)] = float(match.group(2))
    return out


def get_metrics(url, timeout=3.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return parse_prometheus(response.read(4_000_000).decode('utf-8'))


def process_sample(pid):
    """Linux process CPU seconds and resident bytes, without ps parsing."""
    stat = Path(f'/proc/{pid}/stat').read_text()
    # comm is enclosed in parentheses and may contain spaces/parentheses.
    tail = stat.rsplit(') ', 1)[1].split()
    # post-comm fields start at original /proc field 3.
    ticks = int(tail[11]) + int(tail[12])  # utime(14) + stime(15)
    resident_pages = int(tail[21])         # rss(24)
    return {'cpu_seconds': ticks / os.sysconf('SC_CLK_TCK'),
            'rss_bytes': resident_pages * os.sysconf('SC_PAGE_SIZE')}


def managed_pid(component, base=Path('data')):
    """Read the CLI's PID file and reject stale/reused/unrelated processes.

    A CLI-managed background process has a private __*-run argv token.
    This mirrors the Go daemon's process check, rather than matching a
    nonexistent 'red-o detector start' string in /proc/cmdline.
    """
    if component not in ('detector', 'web'):
        raise ValueError('unknown component')
    try:
        pid = int((base / f'{component}.pid').read_text().strip())
        if pid <= 0:
            return None
        argv = (Path('/proc') / str(pid) / 'cmdline').read_bytes().strip(b'\0').split(b'\0')
        if len(argv) < 2 or argv[1] != f'__{component}-run'.encode():
            return None
        stat = (Path('/proc') / str(pid) / 'stat').read_text()
        if stat.rsplit(') ', 1)[1].split()[0] == 'Z':
            return None
        return pid
    except (OSError, ValueError, IndexError):
        return None


def find_process(marker, component='detector'):
    for item in sorted(Path('/proc').iterdir(), key=lambda p: p.name):
        if not item.name.isdigit() or int(item.name) == os.getpid():
            continue
        try:
            args = (item / 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace')
        except (OSError, PermissionError):
            continue
        # Avoid matching commands containing the marker as an incidental argument.
        if ('red-o ' + component + ' ' + marker) in args:
            return int(item.name)
    return None


def resolve_pid(component, explicit=None):
    pid = explicit or managed_pid(component) or find_process('run', component)
    if pid is not None:
        try:
            process_sample(pid)
            return pid
        except (OSError, ValueError, IndexError):
            pass
    return None


def kubectl(*args, timeout=20):
    return subprocess.run(['kubectl', *args], text=True, capture_output=True, timeout=timeout)


def require_pod(namespace, pod):
    result = kubectl('get', 'pod', pod, '-n', namespace, '-o', 'jsonpath={.status.phase}')
    if result.returncode != 0 or result.stdout != 'Running':
        raise RuntimeError(f'Pod {namespace}/{pod} must already be Running: {result.stderr.strip()}')


def poll_process(pid, stop, samples, interval):
    while not stop.is_set():
        try:
            samples.append((time.monotonic(), process_sample(pid)))
        except (OSError, ValueError, IndexError):
            break
        stop.wait(interval)
    try:
        samples.append((time.monotonic(), process_sample(pid)))
    except (OSError, ValueError, IndexError):
        pass


def summarize_process(samples):
    if not samples:
        return {'available': False}
    rss = [s[1]['rss_bytes'] for s in samples]
    cpu = []
    for (t1, a), (t2, b) in zip(samples, samples[1:]):
        if t2 > t1:
            cpu.append(100 * max(0., b['cpu_seconds'] - a['cpu_seconds']) / (t2 - t1))
    return {'available': True, 'rss_bytes': describe(rss), 'cpu_percent_one_core': describe(cpu)}


def workload_script(rate, duration, mode="paced"):
    # Deliberately not a network attack. A process executing 'cat' repeatedly
    # generates observable exec and file-open activity under Tetragon.
    # shell sleep accepts fractional seconds in the test BusyBox image.
    count = max(1, round(rate * duration))
    delay = 1.0 / rate
    pause = f'  sleep {delay:.6f}\n' if mode == "paced" else ""
    return (f'n=0\nwhile [ "$n" -lt {count} ]; do\n'
            '  cat /etc/passwd >/dev/null || exit 9\n'
            '  n=$((n+1))\n'
            f'{pause}'
            'done\nprintf "REDO_COMPLETED=%s\\n" "$n"\n')


@functools.lru_cache(maxsize=1)
def metadata():
    """Best effort environment provenance; no credentials or external network."""
    result = {'hostname': platform.node(), 'kernel': platform.release(),
              'os': platform.platform(), 'python': platform.python_version(),
              'cpu_logical': os.cpu_count(), 'memory_total_bytes': None,
              'kubernetes_server_version': None, 'tetragon_image': None,
              'red_o_version': 'v0.9.1'}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemTotal:'):
                result['memory_total_bytes'] = int(line.split()[1]) * 1024
                break
    except OSError:
        pass
    try:
        version = kubectl('version', '-o', 'json', timeout=7)
        if version.returncode == 0:
            server = json.loads(version.stdout).get('serverVersion', {})
            result['kubernetes_server_version'] = server.get('gitVersion')
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    try:
        ds = kubectl('-n', 'kube-system', 'get', 'daemonset', 'tetragon', '-o', 'json', timeout=7)
        if ds.returncode == 0:
            containers = json.loads(ds.stdout).get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            result['tetragon_image'] = next((c.get('image') for c in containers if c.get('name') == 'tetragon'), None)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return result


def summarize_sweep(runs):
    groups = {}
    for run in runs:
        groups.setdefault(run['target_rate'], []).append(run)
    results = []
    fields = ('actual_actions_per_second', 'normalized_eps',
              'detector_cpu_p95', 'detector_rss_p95_bytes',
              'web_cpu_p95', 'web_rss_p95_bytes')
    for rate, group in sorted(groups.items()):
        row = {'target_rate': rate, 'runs': len(group),
               'completed_actions': sum(r.get('completed_actions') or 0 for r in group),
               'failed_actions': sum(r.get('failed_actions') or 0 for r in group)}
        for field in fields:
            values = [r[field] for r in group if isinstance(r.get(field), (float, int))]
            row[field + '_mean'] = statistics.mean(values) if values else None
            row[field + '_stddev'] = statistics.stdev(values) if len(values) > 1 else (0.0 if values else None)
            row[field + '_p95'] = quantile(values, 95)
        results.append(row)
    return results



def plot_summary_svg(rows, output):
    """Dependency-free, static SVG panels for thesis/review (no invented values)."""
    import html
    panels = [
        ('Observed normalized throughput', 'normalized_eps_mean', 'events/sec'),
        ('Detector CPU P95', 'detector_cpu_p95_mean', '% of one core'),
        ('Detector RSS P95', 'detector_rss_p95_bytes_mean', 'MiB'),
    ]
    width, height = 960, 1000
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img">',
             '<rect width="960" height="1000" fill="#ffffff"/>',
             '<style>text{font-family:Arial, sans-serif;fill:#202b3a} .label{font-size:15px} .title{font-size:22px;font-weight:bold}</style>',
             '<text x="45" y="36" class="title">RED-O v0.9.1 — K3s Performance Sweep</text>']
    for index, (name, field, units) in enumerate(panels):
        y0 = 85 + index * 305
        coords = []
        for row in rows:
            value = row.get(field)
            if value is not None:
                if 'rss' in field:
                    value /= 1048576
                coords.append((float(row['target_rate']), float(value)))
        parts.extend([f'<text x="45" y="{y0}" class="title">{html.escape(name)}</text>',
                      f'<text x="45" y="{y0+25}" class="label">{html.escape(units)} (mean of per-run P95 where applicable)</text>'])
        left, top, graph_width, graph_height = 115, y0+55, 770, 185
        parts.append(f'<path d="M{left} {top} V{top+graph_height} H{left+graph_width}" stroke="#445" fill="none" stroke-width="1.6"/>')
        if coords:
            min_x, max_x = min(x for x, _ in coords), max(x for x, _ in coords)
            max_y = max(y for _, y in coords) * 1.13 or 1.0
            def xmap(x):
                return left + graph_width*(x-min_x)/(max_x-min_x) if max_x > min_x else left+graph_width/2
            def ymap(y):
                return top+graph_height-graph_height*y/max_y
            pts = ' '.join(f'{xmap(x):.1f},{ymap(y):.1f}' for x,y in coords)
            parts.append(f'<polyline points="{pts}" stroke="#156a9e" stroke-width="3" fill="none"/>')
            for x,y in coords:
                xx, yy = xmap(x), ymap(y)
                parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="5" fill="#156a9e"/>')
                parts.append(f'<text x="{xx:.1f}" y="{yy-12:.1f}" text-anchor="middle" font-size="13">{y:.2f}</text>')
                parts.append(f'<text x="{xx:.1f}" y="{top+graph_height+23}" text-anchor="middle" font-size="12">{x:g}</text>')
        parts.append(f'<text x="{left+graph_width/2}" y="{top+graph_height+48}" text-anchor="middle" class="label">Requested actions/sec</text>')
    parts.append('<text x="45" y="982" font-size="12">Observed lab results, not kernel event rate or proven saturation capacity.</text>')
    parts.append('</svg>')
    output.write_text('\n'.join(parts)+'\n', encoding='utf-8')
    return output


def write_report(output, report, rows, headers):
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    csv_file = output.with_suffix('.csv')
    with csv_file.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    return csv_file


def run_load(args):
    require_pod(args.namespace, args.pod)
    before = get_metrics(args.metrics)
    pid = resolve_pid('detector', args.detector_pid)
    if pid is None:
        raise RuntimeError('Cannot find Detector PID; specify --detector-pid')
    process_sample(pid)  # preflight, before generating any workload
    samples, stop = [], threading.Event()
    thread = threading.Thread(target=poll_process, args=(pid, stop, samples, args.sample_interval), daemon=True)
    thread.start()
    web_pid = resolve_pid('web', args.web_pid)
    web_samples = []
    web_thread = None
    if web_pid:
        web_thread = threading.Thread(target=poll_process, args=(web_pid, stop, web_samples, args.sample_interval), daemon=True)
        web_thread.start()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    start = time.monotonic()
    count = max(1, round(args.rate * args.duration))
    command = subprocess.run(['kubectl', 'exec', '-i', '-n', args.namespace, args.pod, '--', 'sh'],
                             input=workload_script(args.rate, args.duration, getattr(args, 'generator_mode', 'paced')), text=True,
                             capture_output=True, timeout=max(30, args.duration * 4 + 30))
    elapsed_workload = time.monotonic() - start
    time.sleep(args.settle)
    after = get_metrics(args.metrics)
    stop.set()
    thread.join(timeout=5)
    if web_thread:
        web_thread.join(timeout=5)
    match = re.search(r'REDO_COMPLETED=(\d+)', command.stdout)
    completed = int(match.group(1)) if match else None
    if command.returncode or completed != count:
        raise RuntimeError(f'workload failed (exit {command.returncode}, completed={completed}, expected={count}): {command.stderr[:1000]}')
    metric_names = ['redo_events_received_total', 'redo_events_normalized_total',
                    'redo_events_invalid_total', 'redo_events_unsupported_total']
    deltas = {}
    for name in metric_names:
        a, b = before.get(name), after.get(name)
        deltas[name] = None if a is None or b is None or b < a else b - a
    elapsed_total = time.monotonic() - start
    observed = deltas['redo_events_normalized_total']
    report = {
        'schema_version': '1.1', 'kind': 'live-k3s-workload-performance',
        'started_at_utc': started_at, 'namespace': args.namespace, 'pod': args.pod,
        'environment': metadata(), 'generator_mode': getattr(args, 'generator_mode', 'paced'),
        'generator_location': 'inside_pod_single_kubectl_exec',
        'generator_pacing_approximate': True,
        'generator_process_returncode': command.returncode,
        'expected_actions': count, 'failed_actions': max(0, count - (completed or 0)),
        'requested_actions_per_second': args.rate, 'requested_duration_seconds': args.duration,
        'completed_actions': completed, 'workload_wall_seconds': elapsed_workload,
        'actual_actions_per_second': completed / elapsed_workload,
        'observation_wall_seconds': elapsed_total,
        'metric_deltas': deltas,
        'normalized_eps_observation_window': None if observed is None else observed / elapsed_total,
        'detector_pid': pid, 'detector_resources': summarize_process(samples),
        'web_pid': web_pid, 'web_resources': summarize_process(web_samples),
        'caveats': [
            'EPS reflects detector counter deltas over workload plus settling time; it is not kernel event generation rate.',
            'One laboratory pod; throughput is not saturation capacity without rate sweeps and backlog/drop checks.',
            'CPU percentage is relative to one logical CPU and can exceed 100%; RSS is the detector process only.',
            'A single kubectl exec starts the in-Pod shell; paced mode still incurs BusyBox sleep and cat overhead.',
            'Burst mode measures an unpaced workload and must not be treated as requested operations/sec.',
            'Baseline cluster activity affects observed data.',
            'No event-loss estimate without independent event-generation ground truth.'],
    }
    rows = [{'requested_rate': args.rate, 'generator_mode': getattr(args, 'generator_mode', 'paced'),
             'expected_actions': count, 'completed_actions': completed, 'failed_actions': report['failed_actions'],
             'actual_actions_per_second': report['actual_actions_per_second'],
             'observation_seconds': elapsed_total,
             'normalized_eps': report['normalized_eps_observation_window'],
             'received': deltas['redo_events_received_total'],
             'normalized': observed,
             'cpu_p50': report['detector_resources'].get('cpu_percent_one_core', {}).get('p50'),
             'cpu_p95': report['detector_resources'].get('cpu_percent_one_core', {}).get('p95'),
             'rss_p95_bytes': report['detector_resources'].get('rss_bytes', {}).get('p95'),
             'web_cpu_p95': report['web_resources'].get('cpu_percent_one_core', {}).get('p95'),
             'web_rss_p95_bytes': report['web_resources'].get('rss_bytes', {}).get('p95')}]
    csv_path = write_report(args.output, report, rows, list(rows[0]))
    print(f'Completed actions: {completed}; normalized EPS (observation window): {report["normalized_eps_observation_window"]}')
    print(f'Reports: {args.output} {csv_path}')
    return report


def alert_ids(path, rule, namespace, pod):
    """Read archived and active alert files, including a rotating active file."""
    paths = sorted(path.parent.glob(path.name + '.segment-*')) + [path]
    found = set()
    for item in paths:
        if not item.exists():
            continue
        with item.open('rb') as stream:
            for line in stream:
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                kubernetes = value.get('kubernetes') or {}
                if (value.get('rule_id') == rule and kubernetes.get('pod') == pod
                        and kubernetes.get('namespace') == namespace and value.get('alert_id')):
                    found.add(value['alert_id'])
    return found


def token_probe_script():
    return ('import socket\n'
            'with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "rb") as f: f.read(1)\n'
            'try:\n'
            ' s=socket.create_connection(("1.1.1.1",80),timeout=1)\n'
            ' s.close()\n'
            'except OSError: pass\n')


def run_latency(args):
    require_pod(args.namespace, args.pod)
    if not args.alerts.exists():
        raise RuntimeError(f'Alert JSONL not found: {args.alerts}. Use Detector soc or forensic mode.')
    rows, measurements = [], []
    for iteration in range(1, args.repeats + 1):
        old = alert_ids(args.alerts, 'R007', args.namespace, args.pod)
        start = time.monotonic()
        command = subprocess.run(['kubectl', 'exec', '-i', '-n', args.namespace, args.pod, '--', 'python3'],
                                 input=token_probe_script(), text=True, capture_output=True, timeout=20)
        if command.returncode:
            raise RuntimeError(f'probe failed: {command.stderr.strip()}')
        deadline = start + args.timeout
        latency = None
        while time.monotonic() < deadline:
            if alert_ids(args.alerts, 'R007', args.namespace, args.pod) - old:
                latency = (time.monotonic() - start) * 1000.0
                break
            time.sleep(args.poll_interval)
        rows.append({'trial': iteration, 'alert_observed': latency is not None,
                     'visibility_from_kubectl_start_ms': latency})
        if latency is not None:
            measurements.append(latency)
        print(f'R007 #{iteration}: {latency:.1f} ms' if latency is not None else f'R007 #{iteration}: timeout')
        time.sleep(args.cooldown)
    report = {'schema_version': '1.1', 'kind': 'live-k3s-alert-visibility-latency',
              'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'environment': metadata(), 'rule': 'R007', 'namespace': args.namespace, 'pod': args.pod,
              'repeats': args.repeats, 'observed': len(measurements),
              'timed_out': args.repeats - len(measurements),
              'visibility_latency_ms': describe(measurements),
              'poll_interval_seconds': args.poll_interval,
              'caveats': [
                  'Measured from host-side kubectl command invocation until alert appears in JSONL.',
                  'Includes kubectl/network/startup, collector, correlation buffering, output and polling delays.',
                  'Not kernel-event-to-alert latency and not a measure of attack success.',
                  'Background events or preexisting simultaneous R007 alerts may confound pod-level matching.',
                  'P99 with few trials is unstable; repeat across independent sessions.']}
    csv_path = write_report(args.output, report, rows,
                            ['trial', 'alert_observed', 'visibility_from_kubectl_start_ms'])
    print(f'Reports: {args.output} {csv_path}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    load = sub.add_parser('load', help='Generate controlled reads and measure Detector counters/CPU/RSS')
    load.add_argument('--namespace', default='security-lab')
    load.add_argument('--pod', default='ebpf-test')
    load.add_argument('--metrics', default='http://127.0.0.1:9095/metrics')
    load.add_argument('--rate', type=float, default=10)
    load.add_argument('--generator-mode', choices=('paced', 'burst'), default='paced',
                      help='paced: sleep between actions inside Pod; burst: no sleep, saturation probe')
    load.add_argument('--duration', type=float, default=20)
    load.add_argument('--settle', type=float, default=3)
    load.add_argument('--sample-interval', type=float, default=0.25)
    load.add_argument('--detector-pid', type=int)
    load.add_argument('--web-pid', type=int)
    load.add_argument('--output', type=Path, default=Path('benchmark-results/performance/load.json'))
    sweep = sub.add_parser('sweep', help='Repeat live load at multiple target rates')
    sweep.add_argument('--namespace', default='security-lab')
    sweep.add_argument('--pod', default='ebpf-test')
    sweep.add_argument('--metrics', default='http://127.0.0.1:9095/metrics')
    sweep.add_argument('--rates', default='5,10,20,40')
    sweep.add_argument('--generator-mode', choices=('paced', 'burst'), default='paced')
    sweep.add_argument('--duration', type=float, default=20)
    sweep.add_argument('--repeats', type=int, default=3)
    sweep.add_argument('--cooldown', type=float, default=3)
    sweep.add_argument('--settle', type=float, default=3)
    sweep.add_argument('--sample-interval', type=float, default=0.25)
    sweep.add_argument('--detector-pid', type=int)
    sweep.add_argument('--web-pid', type=int)
    sweep.add_argument('--output', type=Path, default=Path('benchmark-results/performance/sweep.json'))
    latency = sub.add_parser('latency', help='Measure R007 JSONL visibility after a lab-only probe')
    latency.add_argument('--namespace', default='security-lab')
    latency.add_argument('--pod', default='token-probe')
    latency.add_argument('--alerts', type=Path, default=Path('data/live-alerts.jsonl'))
    latency.add_argument('--repeats', type=int, default=30)
    latency.add_argument('--timeout', type=float, default=15)
    latency.add_argument('--poll-interval', type=float, default=0.1)
    latency.add_argument('--cooldown', type=float, default=0.5)
    latency.add_argument('--output', type=Path, default=Path('benchmark-results/performance/latency.json'))
    args = parser.parse_args(argv)
    if args.command in ('load', 'sweep'):
        if args.command == 'sweep':
            try:
                args.rates = [float(r.strip()) for r in args.rates.split(',')]
            except ValueError:
                parser.error('sweep --rates must be comma-separated numbers')
            if not 1 <= len(args.rates) <= 20 or any(not 0.1 <= r <= 200 for r in args.rates):
                parser.error('sweep: 1..20 rates in range 0.1..200')
            if not 1 <= args.repeats <= 20 or not 0 <= args.cooldown <= 60:
                parser.error('sweep: repeats 1..20 and cooldown 0..60')
        elif not 0.1 <= args.rate <= 200:
            parser.error('load --rate must be 0.1..200')
        if not 1 <= args.duration <= 600:
            parser.error('--duration must be 1..600')
        if not 0 <= args.settle <= 30 or not 0.05 <= args.sample_interval <= 5:
            parser.error('invalid sample interval/settle')
    else:
        if not 1 <= args.repeats <= 500 or not 1 <= args.timeout <= 120:
            parser.error('latency --repeats must be 1..500 and --timeout 1..120')
        if not 0.05 <= args.poll_interval <= 1 or not 0 <= args.cooldown <= 30:
            parser.error('invalid polling/cooldown')
    try:
        if args.command == 'load':
            run_load(args)
        elif args.command == 'sweep':
            runs = []
            root = args.output.with_suffix('')
            for rate in args.rates:
                for repetition in range(1, args.repeats + 1):
                    args.rate = rate
                    args.output = root / f'load-rate-{rate:g}-repeat-{repetition}.json'
                    report = run_load(args)
                    runs.append({'target_rate': rate, 'repetition': repetition,
                                 'actual_actions_per_second': report['actual_actions_per_second'],
                                 'completed_actions': report['completed_actions'],
                                 'failed_actions': report['failed_actions'],
                                 'generator_mode': report['generator_mode'],
                                 'normalized_eps': report['normalized_eps_observation_window'],
                                 'detector_cpu_p95': report['detector_resources'].get('cpu_percent_one_core', {}).get('p95'),
                                 'detector_rss_p95_bytes': report['detector_resources'].get('rss_bytes', {}).get('p95'),
                                 'web_cpu_p95': report['web_resources'].get('cpu_percent_one_core', {}).get('p95'),
                                 'web_rss_p95_bytes': report['web_resources'].get('rss_bytes', {}).get('p95'),
                                 'received': report['metric_deltas']['redo_events_received_total'],
                                 'environment': report['environment']})
                    time.sleep(args.cooldown)
            args.output = root.with_suffix('.json')
            summary = summarize_sweep(runs)
            result = {'schema_version': '1.1', 'kind': 'live-k3s-performance-sweep',
                      'environment': runs[0].get('environment') if runs else metadata(),
                      'generator_mode': args.generator_mode,
                      'runs': runs, 'summary': summary,
                      'caveat': 'No independently verified capture ground truth or full-cluster CPU overhead.'}
            path = write_report(args.output, result, runs, list(runs[0]))
            summary_path = args.output.with_name(args.output.stem + '-summary.csv')
            with summary_path.open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
                writer.writeheader()
                writer.writerows(summary)
            svg_path = args.output.with_suffix('.svg')
            plot_summary_svg(summary, svg_path)
            print(f'Sweep reports: {args.output} {path} {summary_path} {svg_path}')
        else:
            run_latency(args)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f'Benchmark failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
