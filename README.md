# RED-O

**Release: v0.9.3 — Independent Ingester.** This release separates persistent ingestion from Web without changing the threat-detection rules.

RED-O is a laboratory runtime threat-detection system for Kubernetes, written in Go. It consumes Tetragon/eBPF telemetry (and optional Kubernetes Audit), normalizes process/file/network/API events, evaluates rules R001–R022, correlates related activity, and writes JSONL events and alerts. The **independent Ingester** imports JSONL into ClickHouse and persists detector metrics. Web queries ClickHouse and provides incident views, historical metrics, agent status, and exceptions; it does **not** import events or write metrics to ClickHouse.

**Scope:** experimental cybersecurity prototype, not a production intrusion-prevention system. It detects suspicious behavior; it does not block actions or prove compromise.

## Requirements

- Linux and Go **1.23+**.
- Kubernetes/K3s with Tetragon running in `kube-system`, `kubectl` configured with permissions to `exec` into the Tetragon DaemonSet.
- Docker with Compose for ClickHouse (required by Ingester and historical Web views, not required by Detector).
- Tested in a single-node K3s laboratory. The example detection configuration and lab policies assume namespace `security-lab`; adjust configurations for another environment.

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

## Upgrading from v0.9.2: split out Ingester

**Stop the old Web process before starting the new Ingester.** The old Web process still contains the importer and would otherwise race for the same files and checkpoint. Preserve `data/` and the existing `data/web-offsets.json` (do **not** reset it). Back up before changing executables.

```bash
./bin/red-o web stop
./bin/red-o detector stop
# back up working data/, then install/build the updated source
./bin/red-o detector start -event-namespace security-lab
./bin/red-o ingester start
./bin/red-o web start
./bin/red-o ingester status
```

A standalone Ingester can be configured with `-clickhouse`, `-ch-user`, `-events`, `-alerts`, `-offsets`, `-detector-metrics`, `-metrics-instance`, `-metrics-interval`, and `-lock-file`. It uses the `CH_PASSWORD` environment variable for database authentication. If ClickHouse is offline at startup, Ingester retries initialization every five seconds; after a later outage, JSONL import retries without advancing the checkpoint for failed inserts. Check `data/ingester.log` to distinguish a running daemon from a healthy/connected importer.

Web still accepts legacy `-events/-alerts/-offsets` flags but **ignores them with a warning**. Configure these paths on Ingester, not Web. Web no longer needs database permissions to `INSERT` or `CREATE TABLE` (only queries), although writable access to the shared exceptions file is still needed for the exception-management API. For a new installation, start Ingester once to create the ClickHouse tables before relying on Web queries.

**Failure boundaries:** stopping Web no longer pauses import or metrics persistence. If Ingester stops, Detector continues until its pending-segment quota is exhausted. Uncertain ClickHouse acknowledgements can cause duplicate physical rows; `ReplacingMergeTree` does not provide exactly-once semantics. Local JSONL buffering does not restore events lost upstream between Tetragon and Collector.

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

On the reference single-node K3s test, the earlier v0.8.3 investigation observed 500/500 JSONL event IDs in ClickHouse after a simulated database outage, with zero missing/duplicate IDs in the checked sample; 8 old raw segments were replaced by 8 new ones without stopping Detector. These are **test observations**, not universal reliability or losslessness guarantees.

## Benchmark and testing

```bash
./bin/red-o benchmark run -runs 100
python3 tools/live_benchmark.py --help
```

The synthetic benchmark produces `benchmark-results/report.json` and `scenarios.csv` and measures only the detection/correlation engine. It does **not** quantify end-to-end Tetragon throughput, true-positive rates for real attacks, or host CPU overhead. For real-world measurements, collect independent ground truth, durations, process resource statistics, and repeated runs.

## Performance benchmark

The Python 3 **standard-library-only** live benchmark is integrated into the unified
CLI. This is deliberately separated from `benchmark run`, which measures only
the synthetic Go detection engine.

**Preflight:** Run an authorized, isolated single-node K3s laboratory. Detector
and Web should be started once (`detector start`, `web start`). Ensure that
Tetragon TracingPolicies are installed and `security-lab/ebpf-test` is `Running`.
For R007 timing also require `security-lab/token-probe` with its Service Account
Token mounted, and working R007 and TCP tracing. The workload performs
read-only `/etc/passwd` operations inside `ebpf-test`; no exfiltration or
cryptomining is performed. Output files go to ignored `benchmark-results/`.

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

## Security and limitations

- Do not expose port 8088, 9095, or 8123 directly without access controls, authentication, and TLS termination.
- Use a dedicated unprivileged service user where possible; Detector writes JSONL, Ingester reads/rotates them and writes ClickHouse, Web only queries the database and updates lab exceptions. Grant each process only the necessary filesystem permissions.
- Do not commit `data/`, `.env`, runtime logs, metrics snapshots, security tokens, or binaries.
- TracingPolicies depend on kernel/Tetragon behavior and may need adaptation across versions and clusters.
- Correlation alerts are indicators, **not proof** of token exfiltration or compromise.
- This distribution intentionally contains **one Markdown document only: this README**.

## Extended threat scenarios (experimental rules R009–R022)

The extended catalogue is **an indicator-based detection prototype**, not a guarantee that a particular attack succeeded. It builds on R001–R008; legacy baseline rules remain unchanged. Rules are scoped to the laboratory namespace `security-lab` by default. Change `namespace_allow` to monitor other namespaces and tune exclusions before enabling in a shared cluster.

| Scenario | Rule IDs | Evidence and limitations |
|---|---|---|
| Arbitrary commands in a container | R001, R009 | Shell execution; R009 requires an inline `-c` argument. Benign administration may match. |
| Kubernetes credential access | R007, R010 | Open of a projected service-account token, kubeconfig or admin config. R007 additionally correlates token access with a monitored outbound connection. Reading a token does not prove theft. |
| Process privilege elevation | R011, R018, R022 | `security_capset` invocation; privilege-management utility execution; Tetragon's `PRIVILEGES_RAISED_*` binary property on exec, respectively. R011 does **not** verify success. R022 requires Tetragon privilege metadata visibility. |
| Container escape indicators | R012, R017 | Namespace utility execution or monitored runtime socket file operation. Neither establishes successful escape; Unix socket `connect()` may **not** pass through `security_file_open` and R017 is incomplete without Unix-socket telemetry. |
| Internal reconnaissance and services | R013, R019, R020, R021 | Private-subnet TCP attempts, network tooling, correlated shell→internal TCP, and >=5 distinct internal destinations in 30s in the same container. Normal service discovery can trigger alerts. |
| Unauthorized computational-resource use | R014, R015 | Common miner executable names or mining-associated ports. CPU-intensive workloads without these indicators are **not** detected; no CPU anomaly detector is included. |
| Additional containerized workload | R016 | **Successful Kubernetes API audit event** (`create` of Pod/Deployment/DaemonSet/StatefulSet/Job/CronJob, 2xx status). This is evidence of creation through the API, but does not by itself prove that the creation was unauthorized. |

R013 monitors RFC1918 ranges (`10/8`, `172.16/12`, `192.168/16`). Adjust these ranges to the actual PodCIDR and ServiceCIDR to reduce false positives. R021 keeps only bounded in-memory counts, and its state is lost after a restart. These rules may overlap and generate multiple alerts for one incident; tune severity and use existing exception/allowlist mechanisms.

**Additional match fields** available for `configs/rules.json`: `binary_regex`, `arguments_regex`, `path_regex`, `function_in`, `destination_cidrs`, `privileges_raised`, `distinct_destinations`, `window_seconds`, `audit_verbs`, `audit_resources`, `audit_users_exclude`. RE2 regular expressions are compiled when the detector starts; invalid patterns and CIDRs cause configuration validation to fail. A rule combines distinct fields with logical AND and values inside most array fields with OR. `distinct_destinations` counts unique destination IPs per container in a rolling window (and suppresses further alerts in the same window).

### Tetragon policy deployment

The original three laboratory TracingPolicies are retained. Three new **optional** policies were added:

- `deployments/tracing-policies/privilege-capset.yaml`: observes the `security_capset` hook for R011. A hook call is not proof of capability gain.
- `deployments/tracing-policies/runtime-sockets.yaml`: attempts to observe `security_file_open` for relevant runtime socket paths. Not a complete way to detect Unix socket connects.
- `deployments/tracing-policies/kube-credentials.yaml`: broadens file-open visibility to kubeconfig and cluster administration paths. Includes `/home/` and can create significant overhead; tune or disable on busy nodes.

Apply **individually after validating kernel symbols and policy compatibility**. For example:

```bash
kubectl apply -f deployments/tracing-policies/privilege-capset.yaml
kubectl apply -f deployments/tracing-policies/runtime-sockets.yaml
kubectl apply -f deployments/tracing-policies/kube-credentials.yaml
kubectl get tracingpolicies
```

Use the existing `network-connect.yaml` for network rules and `serviceaccount-token.yaml` for R010/R007 token paths. Observe live Tetragon JSON and actual RED-O alerts in the test namespace before claiming that any given rule is validated on K3s.

### Kubernetes Audit for R016 — separate control-plane source

**Tetragon process/network telemetry alone cannot prove a Pod or Deployment was created via the Kubernetes API.** R016 therefore needs the Kubernetes API server audit log, not only TracingPolicies.

A minimal metadata-only policy is provided at `deployments/k3s-audit/policy.yaml`. On a lab K3s server, configure the API server with the equivalent of these arguments (merge into your existing K3s configuration, never overwrite it wholesale):

```yaml
kube-apiserver-arg:
  - audit-policy-file=/var/lib/rancher/k3s/server/audit.yaml
  - audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log
  - audit-log-maxage=7
  - audit-log-maxbackup=5
  - audit-log-maxsize=20
```

Copy the bundled audit policy to the configured absolute path, create the logs directory with appropriate ownership/permissions, and restart K3s **only during an authorized maintenance window**. These configuration changes affect the API server and require cluster-administrator rights. The detector must have read access to the resulting audit log. The upstream K3s hardening guide describes these API server flags.

Start the detector with both sources (after the audit log exists):

```bash
./bin/red-o detector stop
./bin/red-o detector start -event-namespace security-lab \
  -audit-file /var/lib/rancher/k3s/server/logs/audit.log
```

`-audit-file` follows newly appended complete JSONL records and supports basic rename/truncate rotation. By default it starts at EOF; `-audit-from-start` also reads existing records (which can cause duplicate alerts on subsequent restarts). The audit follower **does not have a durable cursor**, and transitions during source failures can lose audit records. The raw log should use restricted permissions and metadata-only logging where possible. Audit data includes usernames. The normalized event only retains metadata, but **forensic raw JSONL stores the original audit record verbatim**: use the supplied metadata-only API audit policy and protect or disable the raw archive as appropriate.

To validate R016 **without changing K3s**, the detector's offline JSONL reader can ingest Kubernetes audit events as well as Tetragon events:

```bash
mkdir -p /tmp/redo-threat-test
./bin/red-o detector run -source jsonl \
  -input tests/fixtures/seven-scenarios.synthetic.jsonl \
  -mode forensic -correlation-lateness 0 \
  -events /tmp/redo-threat-test/events.jsonl \
  -alerts /tmp/redo-threat-test/alerts.jsonl \
  -raw /tmp/redo-threat-test/raw.jsonl
jq -r .rule_id /tmp/redo-threat-test/alerts.jsonl | sort | uniq -c
```

The fixture is synthetic, safe, and explicitly **not** evidence of exploit success. Unit tests include positive/negative cases, namespace isolation, a denied API request, non-final audit stages, out-of-window events, and duplicate destinations.

### Methodology for the dissertation

Treat each scenario as a separately labelled **indicator detection** experiment and record precision/recall against that defined ground truth. Do not treat finding `nsenter`, a capset hook, private network access, or a mining-associated port as proof of exploitation. Validate real capabilities, syscall return values, container identity, legitimate workload context, and authorization through complementary evidence. For R016, evaluate explicit authorized and unauthorized service accounts independently; the prototype does not maintain a permission baseline. Run the K3s tests only in your controlled `security-lab` namespace.
