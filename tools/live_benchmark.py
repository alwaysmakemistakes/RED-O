#!/usr/bin/env python3
"""Opt-in Kubernetes observation test. Requires running RED-O and pre-created lab pods.
No real attacks are executed. Scenario tags only cover controlled lab actions.
"""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

SCENARIOS = {
    "shell-network": ("ebpf-test", ["sh", "-c", "wget -T 3 -O /dev/null http://1.1.1.1/ || true"], ["R003", "R006"]),
    "token-network": ("token-probe", ["python3", "-c", "import socket;f=open('/var/run/secrets/kubernetes.io/serviceaccount/token','rb');f.read(1);f.close();s=socket.socket();s.settimeout(3);\ntry:s.connect(('1.1.1.1',80))\nexcept OSError:pass\nfinally:s.close()"], ["R003", "R007"]),
}

def snapshot(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            text = response.read(2_000_000).decode()
        values = {}
        for line in text.splitlines():
            if line.startswith("redo_") and not line.startswith("#") and "{" not in line:
                k, _, v = line.partition(" ")
                try: values[k] = float(v.strip())
                except ValueError: pass
        return values, None
    except Exception as exc:
        return {}, str(exc)

def read_appended(path, offset):
    # File rotation is not supported by this small lab harness; report it explicitly.
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end < offset:
            raise RuntimeError("Alert file shrank/rotated during experiment")
        f.seek(offset)
        records = []
        for raw in f:
            try: records.append(json.loads(raw))
            except json.JSONDecodeError: continue
        return records

def main():
    parser = argparse.ArgumentParser(description="Opt-in live observation benchmark for RED-O (lab-only)")
    parser.add_argument("--namespace", default="security-lab")
    parser.add_argument("--alerts", default="data/live-alerts.jsonl", type=Path)
    parser.add_argument("--metrics", default="http://127.0.0.1:9095/metrics")
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--wait", type=float, default=6, help="seconds to wait after each action; allow event-time flush")
    parser.add_argument("--output", default="benchmark-results/live-results.json", type=Path)
    parser.add_argument("--kubectl", default="kubectl")
    args = parser.parse_args()
    if not (1 <= args.repeats <= 100 and 3 <= args.wait <= 60): parser.error("repeats: 1..100, wait: 3..60")
    if not args.alerts.is_file(): parser.error(f"missing alert file {args.alerts}; launch detector first")
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    # Preflight pods: no mutation until all chosen targets exist.
    for name in names:
        pod = SCENARIOS[name][0]
        check = subprocess.run([args.kubectl, "get", "pod", pod, "-n", args.namespace, "-o", "jsonpath={.status.phase}"], capture_output=True, text=True)
        if check.returncode or check.stdout.strip() != "Running": parser.error(f"pod {args.namespace}/{pod} not Running: {check.stderr.strip()}")
    results = []
    for name in names:
        pod, command, expected = SCENARIOS[name]
        for n in range(args.repeats):
            offset = args.alerts.stat().st_size
            before, before_error = snapshot(args.metrics)
            began = dt.datetime.now(dt.timezone.utc).isoformat()
            started = time.monotonic()
            call = subprocess.run([args.kubectl, "exec", "-n", args.namespace, pod, "--", *command], capture_output=True, text=True, timeout=30)
            time.sleep(args.wait)
            runtime = time.monotonic() - started
            after, after_error = snapshot(args.metrics)
            items = read_appended(args.alerts, offset)
            # Pod-scoped attribution is best effort; other activity may occur concurrently.
            own = [a for a in items if (a.get("kubernetes") or {}).get("pod") == pod]
            got = [a.get("rule_id", "") for a in own]
            missing = [r for r in expected if r not in got]
            result = {"scenario":name,"iteration":n+1,"pod":pod,"started_at":began,"wall_seconds":round(runtime,3),
                      "command_exit_code":call.returncode,"expected_rules":expected,"observed_rules":got,"missing_rules":missing,
                      "pass_observation":call.returncode==0 and not missing,"new_alerts_all_pods":len(items),
                      "metrics_before_error":before_error,"metrics_after_error":after_error,
                      "metric_deltas":{k:after[k]-before[k] for k in before.keys()&after.keys() if k.endswith("_total")}}
            results.append(result)
            print(f"{name} #{n+1}: {'OBSERVED' if result['pass_observation'] else 'CHECK'} rules={got} missing={missing} new_alerts={len(items)}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary = {"kind":"live-lab-observation","note":"Not a precision/recall estimate: events may be dropped, competing workloads may emit alerts, and rule exclusions affect observations.","results":results}
    args.output.write_text(json.dumps(summary, indent=2)+"\n")
    csv_path = args.output.with_suffix(".csv")
    with csv_path.open("w",newline="") as f:
        writer=csv.writer(f); writer.writerow(["scenario","iteration","pod","command_exit_code","observed_rules","missing_rules","pass_observation","wall_seconds","new_alerts_all_pods"])
        for r in results: writer.writerow([r["scenario"],r["iteration"],r["pod"],r["command_exit_code"],";".join(r["observed_rules"]),";".join(r["missing_rules"]),r["pass_observation"],r["wall_seconds"],r["new_alerts_all_pods"]])
    print("Results:",args.output,"and",csv_path)

if __name__ == "__main__": main()
