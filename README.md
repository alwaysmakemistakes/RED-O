# RED-O

RED-O is a laboratory runtime threat-detection system for Kubernetes, written in Go. It consumes Tetragon/eBPF telemetry. The **independent Ingester** imports JSONL into ClickHouse and persists detector metrics. Web queries ClickHouse and provides incident views, historical metrics, agent status, and exceptions; it does **not** import events or write metrics to ClickHouse.

## Requirements

- Linux and Go **1.23+**.
- Kubernetes/K3s with Tetragon running in `kube-system`, `kubectl` configured with permissions to `exec` into the Tetragon DaemonSet.
- Docker with Compose for ClickHouse (required by Ingester and historical Web views, not required by Detector).

## Install and run

```bash
# After cloning this repository, from its root:
go test -count=1 ./...
go vet ./...
mkdir -p bin
go build -o bin/red-o ./cmd/red-o

# Apply lab tracing policies (Tetragon must already be installed):
kubectl apply -f deployments/tracing-policies/
kubectl get tracingpolicies

# Database for Ingester and historical Web views:
cp .env.example .env
# Edit .env; set secure WEB_PASSWORD and CH_PASSWORD before exposing the service.
docker compose --env-file .env -f deployments/clickhouse/compose.yaml up -d
set -a; . ./.env; set +a

# Starts in the background, returns the terminal immediately:
./bin/red-o detector start -event-namespace security-lab

# Start the independent importer (returns terminal immediately):
./bin/red-o ingester start

# Start the read/query Web server in the background:
./bin/red-o web start

# Verify all three services:
./bin/red-o detector status
./bin/red-o ingester status
./bin/red-o web status
```

The Web interface is at `http://127.0.0.1:8088` and binds to loopback by default. Without `WEB_USER`/`WEB_PASSWORD`, the local lab fallback is `admin/admin`; **never expose these demo credentials to a network**. Prefer SSH port forwarding for remote access. ClickHouse also uses a demo password by default; changing a persisted ClickHouse volume's password requires updating its server configuration, not just `.env`.

The Detector does not require the Ingester, Web server or ClickHouse to detect threats; it can run alone. If Ingester is stopped, JSONL and alert segments accumulate until the configured quota is exhausted. If Web is stopped, Ingester **continues importing** into ClickHouse.

## Detector, Ingester and Web commands — terminal remains available

| Command | Behavior |
|---|---|
| `./bin/red-o detector start [flags]` | Launches one detached Detector and **returns the shell prompt**. |
| `./bin/red-o detector status` | Reports whether the managed Detector is running. |
| `./bin/red-o detector stop` | Gracefully stops the managed Detector (SIGINT). |
| `./bin/red-o detector logs` | Prints the Detector log. For live output use `tail -f data/detector.log`. |
| `./bin/red-o detector run [flags]` | Foreground mode for debugging; Ctrl+C stops it. |
| `./bin/red-o ingester start [flags]` | Starts JSONL → ClickHouse ingestion and metrics persistence in the background. |
| `./bin/red-o ingester status` | Reports whether the managed Ingester process exists. |
| `./bin/red-o ingester stop` | Gracefully stops Ingester (SIGINT). |
| `./bin/red-o ingester logs` | Prints Ingester logs; `tail -f data/ingester.log` follows them live. |
| `./bin/red-o ingester run [flags]` | Runs Ingester in foreground (Ctrl+C). |
| `./bin/red-o web start [flags]` | Starts Web in the background and returns the shell prompt. |
| `./bin/red-o web status` | Reports whether managed Web is running. |
| `./bin/red-o web stop` | Gracefully stops managed Web (SIGINT). |
| `./bin/red-o web logs` | Prints Web log; use `tail -f data/web.log` for live output. |
| `./bin/red-o web run [flags]` | Runs Web in the foreground for debugging; Ctrl+C stops it. |
| `./bin/red-o benchmark run -runs 100` | Runs synthetic, labelled Rule Engine/Correlator tests. |
| `./bin/red-o benchmark performance load ...` | Measures live normalized EPS and Detector/Web CPU/RSS in K3s. |
| `./bin/red-o benchmark performance sweep ...` | Runs repeated workload levels, exports JSON/CSV. |
| `./bin/red-o benchmark performance latency ...` | Measures R007 alert-visibility timing percentiles. |

The background Detector uses `data/detector.pid` and `data/detector.log`; Ingester uses `data/ingester.pid`, `data/ingester.log`; and Web uses `data/web.pid`, `data/web.log`. These files are excluded from Git. A second managed instance of each component is refused. Ingester additionally holds `data/ingester.instance.lock` for its lifetime, preventing simultaneous foreground/background importers from sharing the same files. Only run **one Ingester per checkpoint and JSONL pair**. The PID is checked against the daemon's command line before issuing a stop signal. Background mode **does not install a systemd service, auto-start on reboot, or guarantee Kubernetes connectivity**: inspect `status`, `logs`, and heartbeat after launch. For production-like lab restarts, configure a systemd service separately.

Run from the project directory (or keep `bin/red-o` inside the project); the CLI discovers `configs/rules.json` to locate its files. To make `red-o` callable without `./bin/`, add the project's `bin` directory to `PATH`. The legacy `cmd/detector` and `cmd/web` entry points remain for compatibility but run in foreground. The legacy Web binary no longer imports JSONL; use the unified `red-o ingester` command.

### Modes and flags

```bash
# Normal SOC mode (default):
./bin/red-o detector start -event-namespace security-lab

# Forensic test; all normalized and raw events are logged:
./bin/red-o detector start -mode forensic -event-namespace security-lab \
  -storage-max-bytes 65536 -storage-max-segments 32 \
  -raw-max-segments 8 -raw-max-storage 8388608 -raw-retention 24h

./bin/red-o detector status
./bin/red-o detector stop
```

Stop the current managed detector before changing its flags. Do not run two Detectors on the same output files or two Ingester processes against the same checkpoints.

Modes: `soc` stores alerts and alert-related events; `forensic` stores raw telemetry, all supported normalized events, and alerts; `lightweight` stores alerts only. Detection and correlation remain enabled in each mode. Prometheus metrics: `http://127.0.0.1:9095/metrics` when the detector is running.


## Storage and recovery

| Stream | Default file | Retention |
|---|---|---|
| Normalized events | `data/live-events.jsonl` | Rotated segments are preserved until Ingester confirms successful ClickHouse import. |
| Alerts | `data/live-alerts.jsonl` | Same fail-closed retention as events. |
| Raw Tetragon telemetry | `data/raw.jsonl` in forensic or `-soc-raw` mode | Separate bounded retention; oldest *closed raw-only* segments may be deleted. |

Defaults: 64 MiB max active segment (`-storage-max-bytes`), 32 pending event/alert segments (`-storage-max-segments`), and for raw telemetry 24h (`-raw-retention`), 32 segments (`-raw-max-segments`), 2 GiB (`-raw-max-storage`). Raw retention may intentionally discard old *raw* segments to keep the Detector operational. On overflow of pending **event or alert** segments, writing fails rather than silently deleting unimported data.

Ingester stores its ingestion checkpoint in `data/web-offsets.json` **for backwards compatibility**. Do not rename/delete this file when upgrading from v0.9.2: preserving it prevents replay of already imported records. The importer tracks file identity, handles completed JSONL lines, and advances its checkpoint after successful import. It processes archived segments before the active file. Ingester persists metrics history to ClickHouse (`runtime_security.detector_metrics`, TTL 30 days; `-metrics-interval 5s` by default). Web reads the same history and supports 10-minute, 1-hour, and 24-hour views. Web may poll Detector metrics to display current availability, **but does not insert metrics**; Ingester owns all ClickHouse inserts and table initialization.

**Delivery is not exactly-once in all failure modes**: a lost ClickHouse acknowledgement may cause retries; asynchronous MergeTree merges may affect duplicate-row counts. Events lost upstream during a Tetragon/Collector disconnect cannot be reconstructed by JSONL buffering. Power failure can lose recently buffered disk writes.

### Live K3s storage verification

`tools/verify_storage_recovery.py` supports snapshots and ID reconciliation during a controlled database outage:

```bash
python3 tools/verify_storage_recovery.py capture --label before
# In a disposable lab only: stop ClickHouse, generate permitted test events,
# and capture while the database is still stopped:
python3 tools/verify_storage_recovery.py capture --label outage
# Restore ClickHouse and allow Web to import buffered segments:
python3 tools/verify_storage_recovery.py verify
```

Results are written under `benchmark-results/storage-recovery/`. Back up `data/` and ensure the Detector and Web are running before the experiment. The helper assumes the local Docker Compose ClickHouse container and should only be used in an authorized laboratory.

## Benchmark and testing

```bash
./bin/red-o benchmark run -runs 100
python3 tools/live_benchmark.py --help
```

The synthetic benchmark produces `benchmark-results/report.json` and `scenarios.csv` and measures only the detection/correlation engine.

## Performance benchmark

```bash
# Small baseline and controlled rate sweep (3 independent trials per rate):
./bin/red-o benchmark performance sweep \
  --namespace security-lab --pod ebpf-test \
  --rates 5,10,20,40 --duration 20 --repeats 3 \
  --generator-mode paced

# Single run, inspect JSON and CSV:
./bin/red-o benchmark performance load \
  --rate 20 --duration 30 \
  --output benchmark-results/performance/load-20.json

# A bounded unpaced burst (separate generator capacity experiment):
./bin/red-o benchmark performance load \
  --rate 80 --duration 10 --generator-mode burst \
  --output benchmark-results/performance/burst.json

# Optional R007 latency/visibility probe. Requires token-probe Pod:
./bin/red-o benchmark performance latency \
  --pod token-probe --repeats 30 --timeout 15 \
  --alerts data/live-alerts.jsonl
```

The `sweep` reports are `benchmark-results/performance/sweep.json` and
`sweep.csv`, `sweep-summary.csv` (mean, sample standard deviation and P95
across repetitions) and `sweep.svg` (dependency-free plot), plus detailed
per-run files under `benchmark-results/performance/sweep/`.
The latency reports are `latency.json` and `latency.csv` with
P50/P95/P99 calculated by linear interpolation on successful samples. Timeouts
are counted separately and **excluded** from percentile calculations; report
the observation rate alongside percentiles. With fewer than about 100 trials,
the P99 estimate is particularly unstable. Results are not automatically
representative of production workloads.

## Layout

```text
cmd/red-o/                  Unified three-service CLI
cmd/detector/, cmd/web/     Legacy foreground entry points
internal/ingester/          Independent JSONL importer, checkpoints, metrics writer
internal/metricsscrape/     Shared loopback-only Prometheus parser
internal/webapp/            Read/query Web API, UI, local availability monitoring
internal/                   Collector, normalization, detection, correlation, storage, tests
configs/                    Rule definitions R001–R022
  correlations.json         Runtime event correlations
  rules.json                Single-event detections
deployments/tracing-policies/  Lab Tetragon policies
deployments/clickhouse/      Local ClickHouse Compose
scripts/, tools/, tests/     Utilities, recovery/benchmark helpers, fixtures (where present)
```
