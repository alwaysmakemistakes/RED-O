#!/usr/bin/env python3
"""RED-O v0.9.4: isolated, reproducible two-sensor event-time experiments.

Runs four finite JSONL sensor streams via FIFOs. No cluster access is needed.
Works from project root; outputs never touch data/ or a running Detector.
"""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
from urllib.request import urlopen

UTC = dt.timezone.utc
METRIC_NAMES = (
    "redo_sensor_merge_pending_events",
    "redo_sensor_merge_late_total",
    "redo_sensor_merge_forced_total",
    "redo_sensor_future_skew_total",
    "redo_alerts_total",
    "redo_events_normalized_total",
)


def iso(base, seconds):
    return (base + dt.timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def process(base, t, binary, execid):
    return {
        "time": iso(base, t), "node_name": "node-a",
        "process_exec": {"process": {
            "binary": binary, "exec_id": execid, "parent_exec_id": "", "pid": 200,
            "uid": 0, "pod": {"namespace": "security-lab", "name": "ebpf-test",
                              "uid": "lab-pod-uid", "container": {"name": "lab", "id": "lab-container-uid"}}
        }}
    }


def file_access(base, t):
    o = process(base, t, "/bin/cat", "cat")
    p = o.pop("process_exec")["process"]
    p["parent_exec_id"] = "shell"
    o["process_kprobe"] = {"function_name": "security_file_open",
                           "args": [{"file_arg": {"path": "/etc/passwd"}}], "process": p}
    return o


def network(base, t):
    o = process(base, t, "/bin/wget", "wget")
    p = o.pop("process_exec")["process"]
    p["parent_exec_id"] = "shell"
    o["process_kprobe"] = {"function_name": "tcp_connect", "args": [{"sock_arg": {
        "family": "AF_INET", "protocol": "TCP", "daddr": "1.1.1.1", "dport": 443}}], "process": p}
    return o


def schedule(case, base):
    # Each value is (wall-clock offset in seconds, input JSON); *event time*
    # is embedded in JSON and intentionally differs from arrival time.
    if case == "A_reorder":
        return {
            "fast": [(0.10, network(base, 3)), (1.35, process(base, 9, "/bin/true", "noop-a"))],
            "slow": [(0.55, process(base, 1, "/bin/sh", "shell")),
                     (0.90, file_access(base, 2)),
                     (1.60, process(base, 10, "/bin/true", "noop-b"))],
        }, 2.35, 40
    if case == "B_too_late":
        return {
            "fast": [(0.10, network(base, 3)), (0.30, process(base, 9, "/bin/true", "noop-a"))],
            "slow": [(0.55, process(base, 10, "/bin/true", "noop-b")),
                     (1.35, process(base, 1, "/bin/sh", "shell"))],
        }, 2.35, 40
    if case == "C_idle_flush":
        return {"fast": [(0.10, process(base, 1, "/bin/sh", "shell"))], "slow": []}, 5.70, 40
    if case == "D_force_release":
        return {
            "fast": [(0.10 + i * 0.22, process(base, i + 1, "/bin/true", f"noop-{i}")) for i in range(5)],
            "slow": [],
        }, 2.35, 2
    raise ValueError(case)


def choose_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def metrics_snapshot(port):
    try:
        raw = urlopen(f"http://127.0.0.1:{port}/metrics", timeout=0.18).read().decode()
    except Exception:
        return {}
    observed = {}
    for line in raw.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        label, number = line.split(" ", 1)
        name = label.split("{", 1)[0]
        if name in METRIC_NAMES:
            try:
                observed[name] = float(number.strip())
            except ValueError:
                pass
    return observed


def read_jsonl(path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def run_case(project, output, case):
    d = output / case
    d.mkdir(parents=True, exist_ok=False)
    base = dt.datetime.now(UTC) - dt.timedelta(seconds=30)
    streams, keep_open, buffer_size = schedule(case, base)
    for name in ("fast", "slow"):
        os.mkfifo(d / (name + ".fifo"), mode=0o600)
    cfg = {"schema_version": "1.0", "sensors": [
        {"id": name, "type": "jsonl", "cluster": "lab-k3s", "node": "node-a", "path": str(d / (name + ".fifo"))}
        for name in ("fast", "slow")
    ]}
    (d / "sensors.json").write_text(json.dumps(cfg, indent=2) + "\n")
    port = choose_port()
    command = [str(project / "bin/red-o"), "detector", "run", "-source", "multi", "-sensors", str(d / "sensors.json"),
               "-mode", "forensic", "-rules", "configs/rules.json", "-correlations", "configs/correlations.json",
               "-sensor-lateness", "2s", "-sensor-idle-timeout", "4s", "-sensor-buffer", str(buffer_size),
               "-correlation-lateness", "0", "-metrics-listen", f"127.0.0.1:{port}",
               "-heartbeat", "", "-gap-log", "", "-events", str(d / "events.jsonl"),
               "-raw", str(d / "raw.jsonl"), "-alerts", str(d / "alerts.jsonl")]
    start = time.monotonic()
    history, sends, thread_errors = [], [], []
    log = (d / "detector.log").open("w")
    proc = subprocess.Popen(command, cwd=project, stdout=log, stderr=subprocess.STDOUT)

    def writer(name, records):
        try:
            # FIFO blocks until the detector reader opens this source.
            with (d / (name + ".fifo")).open("w", buffering=1) as f:
                for offset, payload in records:
                    while True:
                        left = start + offset - time.monotonic()
                        if left <= 0:
                            break
                        time.sleep(min(left, 0.02))
                    f.write(json.dumps(payload, separators=(",", ":")) + "\n")
                    sends.append({"sensor": name, "received_schedule_seconds": round(time.monotonic() - start, 3),
                                  "event_timestamp": payload["time"],
                                  "binary": payload.get("process_exec", {}).get("process", {}).get("binary") or
                                            payload.get("process_kprobe", {}).get("process", {}).get("binary")})
                while time.monotonic() - start < keep_open:
                    time.sleep(0.025)
        except Exception as e:
            thread_errors.append(f"{name}: {e}")

    threads = [threading.Thread(target=writer, args=(name, records), daemon=True) for name, records in streams.items()]
    for th in threads:
        th.start()
    try:
        while proc.poll() is None and time.monotonic() - start < keep_open + 9:
            t = round(time.monotonic() - start, 3)
            snap = metrics_snapshot(port)
            if snap:
                history.append({"elapsed_seconds": t, **snap})
            time.sleep(0.095)
        if proc.poll() is None:
            proc.terminate()
        rc = proc.wait(timeout=5)
        for th in threads:
            th.join(timeout=2)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log.close()
    (d / "metrics-timeline.json").write_text(json.dumps(history, ensure_ascii=False, indent=2) + "\n")
    (d / "send-schedule.json").write_text(json.dumps(sorted(sends, key=lambda s: s["received_schedule_seconds"]), indent=2) + "\n")
    entries = read_jsonl(d / "events.jsonl")
    alerts = read_jsonl(d / "alerts.jsonl")
    text = (d / "detector.log").read_text()
    m = re.search(r"multi-sensor merge: pending=(\d+) late=(\d+) forced=(\d+)", text)
    stats = dict(zip(("pending", "late", "forced"), (int(x) for x in m.groups()))) if m else None
    first_alert = next((s["elapsed_seconds"] for s in history if s.get("redo_alerts_total", 0) >= 1), None)
    alerts_by_rule = {}
    for a in alerts:
        alerts_by_rule[a["rule_id"]] = alerts_by_rule.get(a["rule_id"], 0) + 1
    max_pending = max((s.get("redo_sensor_merge_pending_events", 0) for s in history), default=0)
    max_late = max((s.get("redo_sensor_merge_late_total", 0) for s in history), default=0)
    max_forced = max((s.get("redo_sensor_merge_forced_total", 0) for s in history), default=0)
    by_id = {e["event_id"]: e for e in entries}
    r005 = [a for a in alerts if a.get("rule_id") == "R005"]
    r005_order = ([by_id[x]["timestamp"] for x in r005[0]["related_event_ids"] if x in by_id] if r005 else [])
    r005_sensors = r005[0].get("sensor_ids", []) if r005 else []
    conditions = {
        "A_reorder": stats is not None and stats["late"] == 0 and stats["forced"] == 0
            and len(r005) >= 1 and r005_order == sorted(r005_order) and len(r005_order) == 3
            and set(r005_sensors) == {"fast", "slow"},
        "B_too_late": stats is not None and stats["late"] >= 1 and not any(a["rule_id"] == "R006" for a in alerts),
        "C_idle_flush": stats is not None and first_alert is not None and first_alert >= 3.5
            and first_alert < keep_open and max_pending >= 1,
        "D_force_release": stats is not None and stats["forced"] >= 3 and len(entries) == 5,
    }
    report = {"case": case, "pass": rc == 0 and not thread_errors and conditions[case],
              "exit_code": rc, "writer_errors": thread_errors, "sent_records": len(sends),
              "normalized_events": len(entries), "alerts": len(alerts), "alerts_by_rule": alerts_by_rule,
              "merge_stats": stats, "max_pending_samples": max_pending, "max_late_samples": max_late,
              "max_forced_samples": max_forced, "first_alert_elapsed_seconds": first_alert,
              "r005_related_event_times": r005_order, "r005_sensor_ids": r005_sensors,
              "sensor_lateness_seconds": 2, "sensor_idle_timeout_seconds": 4,
              "correlation_lateness_seconds": 0, "buffer": buffer_size,
              "duration_seconds": round(time.monotonic() - start, 3)}
    (d / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    for fifo in d.glob("*.fifo"):
        fifo.unlink()
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", default=".", help="RED-O v0.9.4 checkout containing bin/red-o")
    p.add_argument("--output", default=None, help="fresh results directory (must not exist)")
    args = p.parse_args()
    project = Path(args.project).resolve()
    if not (project / "bin/red-o").is_file() or not (project / "configs/correlations.json").is_file():
        p.error("--project must point to a built RED-O checkout")
    if args.output:
        output = Path(args.output).resolve()
    else:
        output = (project / "benchmark-results" / ("watermark-exp-" + dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))).resolve()
    if output.exists():
        p.error("output directory already exists; use a new name to avoid overwriting evidence")
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for case in ("A_reorder", "B_too_late", "C_idle_flush", "D_force_release"):
        print(f"Running {case}...", flush=True)
        result = run_case(project, output, case)
        results.append(result)
        print(f"  pass={result['pass']} received={result['sent_records']} normalized={result['normalized_events']} "
              f"alerts={result['alerts']} merger={result['merge_stats']}", flush=True)
    (output / "summary.json").write_text(json.dumps({"schema_version": "1.0", "tool": "red-o-v0.9.4-watermark-experiment",
        "results": results, "all_pass": all(r["pass"] for r in results)}, indent=2, ensure_ascii=False) + "\n")
    with (output / "summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case", "pass", "sent", "normalized", "alerts", "pending_end", "late_end", "forced_end", "first_alert_seconds"])
        for r in results:
            stats = r.get("merge_stats") or {}
            w.writerow([r["case"], r["pass"], r["sent_records"], r["normalized_events"], r["alerts"],
                        stats.get("pending", ""), stats.get("late", ""), stats.get("forced", ""),
                        r["first_alert_elapsed_seconds"]])
    print(f"\nAll PASS: {all(r['pass'] for r in results)}\nResults: {output}")
    return 0 if all(r["pass"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
