package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime-detector/internal/benchmark"
	"runtime-detector/internal/detectorapp"
	"runtime-detector/internal/ingester"
	"runtime-detector/internal/quality"
	"runtime-detector/internal/webapp"
	"strings"
	"time"
)

const defaultCHPassword = "redo-local-change-me"

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage()
		return 0
	}
	if args[0] == "setup" {
		return setupCommand(args[1:])
	}
	if args[0] == "up" {
		return upCommand(args[1:])
	}
	if args[0] == "down" {
		return downCommand(args[1:])
	}
	if args[0] == "status" {
		return allStatusCommand(args[1:])
	}
	if args[0] == "credentials" {
		return credentialsCommand(args[1:])
	}
	if args[0] == "version" || args[0] == "--version" {
		return versionCommand(args[1:])
	}
	if args[0] == "doctor" {
		return doctorCommand(args[1:])
	}
	if len(args) >= 1 && args[0] == detectorChildCommand {
		detectorapp.Run(append(detectorDefaults(), args[1:]...))
		return 0
	}
	if len(args) >= 1 && args[0] == webChildCommand {
		runWebForeground(args[1:])
		return 0
	}
	if len(args) >= 1 && args[0] == ingesterChildCommand {
		if err := runIngesterForeground(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) >= 2 && args[0] == "benchmark" && args[1] == "quality" {
		return qualityCommand(args[2:])
	}
	if len(args) >= 2 && args[0] == "benchmark" && args[1] == "performance" {
		return performanceCommand(args[2:])
	}
	if len(args) >= 2 && args[0] == "benchmark" && args[1] == "run" {
		return benchmarkCommand(args[2:])
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Expected: red-o detector|ingester|web start|stop|status|run|logs")
		usage()
		return 2
	}
	component, action := args[0], args[1]
	if component != "detector" && component != "web" && component != "ingester" {
		fmt.Fprintln(os.Stderr, "Unknown component:", component)
		return 2
	}
	if component == "web" && action != "start" && action != "stop" && action != "status" && action != "run" && action != "logs" {
		fmt.Fprintln(os.Stderr, "Unknown web action:", action)
		return 2
	}
	if component == "ingester" && action != "start" && action != "stop" && action != "status" && action != "run" && action != "logs" {
		fmt.Fprintln(os.Stderr, "Unknown ingester action:", action)
		return 2
	}
	if component == "detector" && action != "start" && action != "stop" && action != "status" && action != "run" && action != "logs" {
		fmt.Fprintln(os.Stderr, "Unknown detector action:", action)
		return 2
	}
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Configuration error:", err)
		return 1
	}
	if err := os.Chdir(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll("data", 0700); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create data directory:", err)
		return 1
	}
	if component == "detector" {
		switch action {
		case "start":
			if err := startDetectorInBackground(args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "stop":
			if err := stopDetector(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "status":
			return statusDetector()
		case "logs":
			if err := tailDetectorLog(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "run":
			fmt.Println("RED-O detector running in foreground (Ctrl+C to stop)")
			detectorapp.Run(append(detectorDefaults(), args[2:]...))
			return 0
		}
	}
	if component == "ingester" {
		switch action {
		case "start":
			if err := startIngesterInBackground(args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "stop":
			if err := stopIngester(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "status":
			return statusIngester()
		case "logs":
			if err := tailIngesterLog(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "run":
			if err := runIngesterForeground(args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		}
	}
	switch action {
	case "start":
		if err := startWebInBackground(args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "stop":
		if err := stopWeb(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "status":
		return statusWeb()
	case "logs":
		if err := tailWebLog(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "run":
		runWebForeground(args[2:])
		return 0
	}
	return 2
}
func runWebForeground(args []string) {
	if err := loadLocalSettings(); err != nil {
		fmt.Fprintln(os.Stderr, "Web settings:", err)
		return
	}
	if os.Getenv("WEB_USER") == "" {
		os.Setenv("WEB_USER", "admin")
	}
	if os.Getenv("WEB_PASSWORD") == "" {
		os.Setenv("WEB_PASSWORD", "admin")
		fmt.Fprintln(os.Stderr, "WARNING: using demo Web credentials admin/admin on localhost. Set WEB_USER and WEB_PASSWORD before exposing access.")
	}
	if os.Getenv("CH_PASSWORD") == "" {
		os.Setenv("CH_PASSWORD", defaultCHPassword)
	}
	// Never expose the legacy demo account admin/admin on a non-loopback listener.
	// The portable setup generates a unique password in private .env instead.
	addr := "127.0.0.1:8088"
	for i := 0; i < len(args); i++ {
		if args[i] == "-listen" && i+1 < len(args) {
			addr = args[i+1]
		}
		if strings.HasPrefix(args[i], "-listen=") {
			addr = strings.TrimPrefix(args[i], "-listen=")
		}
	}
	if isRemoteDemoCredentials(addr, os.Getenv("WEB_USER"), os.Getenv("WEB_PASSWORD")) {
		fmt.Fprintln(os.Stderr, "refusing insecure demo credentials admin/admin on non-loopback Web listener; run 'red-o setup' to generate unique credentials")
		return
	}
	defaults := []string{"-listen", "127.0.0.1:8088", "-clickhouse", "http://127.0.0.1:8123", "-exceptions", "data/exceptions.json", "-heartbeat", "data/collector-heartbeat.json", "-detector-metrics", "http://127.0.0.1:9095/metrics"}
	fmt.Println("RED-O Web running in foreground (Ctrl+C to stop)")
	webapp.Run(append(defaults, args...))
}

func runIngesterForeground(args []string) error {
	if err := loadLocalSettings(); err != nil {
		return err
	}
	if os.Getenv("CH_PASSWORD") == "" {
		os.Setenv("CH_PASSWORD", defaultCHPassword)
	}
	fmt.Println("RED-O Ingester running in foreground (Ctrl+C to stop)")
	return ingester.Run(args)
}

func performanceCommand(args []string) int {
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	script := filepath.Join(root, "tools", "performance_benchmark.py")
	if _, err := os.Stat(script); err != nil {
		fmt.Fprintln(os.Stderr, "performance benchmark script missing:", err)
		return 1
	}
	cmd := exec.Command("python3", append([]string{script}, args...)...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "performance benchmark:", err)
		return 1
	}
	return 0
}

func benchmarkCommand(args []string) int {
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = os.Chdir(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fs := flag.NewFlagSet("benchmark run", flag.ContinueOnError)
	runs := fs.Int("runs", 20, "repetitions of each labelled synthetic scenario")
	lateness := fs.Duration("lateness", 2*time.Second, "allowed event-time lateness")
	buffer := fs.Int("buffer", 256, "maximum pending correlation events per container")
	output := fs.String("output", "benchmark-results", "output folder for report.json and scenarios.csv")
	rules := fs.String("rules", "configs/rules.json", "detection rules file")
	correlations := fs.String("correlations", "configs/correlations.json", "correlation rules file")
	if err = fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments:", fs.Args())
		return 2
	}
	r, err := benchmark.Run(benchmark.Options{Runs: *runs, Lateness: *lateness, Buffer: *buffer, RulesFile: *rules, CorrelationsFile: *correlations})
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		return 1
	}
	if err = benchmark.Write(r, filepath.Join(*output, "report.json"), filepath.Join(*output, "scenarios.csv")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Synthetic benchmark: scenarios=%d runs=%d events=%d TP=%d FP=%d FN=%d precision=%.3f recall=%.3f f1=%.3f\n", len(r.Scenarios), *runs, r.Events, r.TP, r.FP, r.FN, r.Precision, r.Recall, r.F1)
	fmt.Printf("Engine-only throughput: %.1f events/s (not end-to-end)\n", r.EngineEventsPerSecond)
	fmt.Printf("Results: %s/report.json and %s/scenarios.csv\n", *output, *output)
	return 0
}
func findProjectRoot() (string, error) {
	candidates := []string{}
	wd, _ := os.Getwd()
	candidates = append(candidates, wd)
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, dir, filepath.Dir(dir))
	}
	for _, dir := range candidates {
		for i := 0; i < 3; i++ {
			if _, err := os.Stat(filepath.Join(dir, "configs", "rules.json")); err == nil {
				return filepath.Abs(dir)
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("cannot locate configs/rules.json; run from repository or place binary under repository/bin")
}
func usage() {
	fmt.Println(strings.TrimSpace(`RED-O — runtime threat detector
Usage:
  red-o setup [-audit auto|off|required] [-event-namespace NAME]    # discover Kubernetes/Tetragon and generate private credentials
  red-o up [-storage auto|jsonl|clickhouse] [-web-listen HOST:PORT]  # first-run setup and services
  red-o down | status                       # managed components
  red-o credentials [show|rotate]          # per-installation initial Web account
  red-o version [-json]                     # release and build information
  red-o doctor [-sensors configs/sensors.json] [-kubernetes] [-clickhouse] [-json]  # read-only preflight
  red-o detector start [detector flags]   # background; returns terminal
  red-o detector stop | status | logs
  red-o detector run [detector flags]     # foreground
  red-o detector start -source multi -sensors configs/sensors.json  # parallel sensors
  red-o ingester start [ingester flags]  # background; imports JSONL + persists metrics
  red-o ingester stop | status | logs
  red-o ingester run [ingester flags]    # foreground
  red-o web start [web flags]        # background; returns terminal
  red-o web stop | status | logs
  red-o web run [web flags]          # foreground
  red-o benchmark run [-runs 20] [-output benchmark-results]
  red-o benchmark performance load|sweep|latency [flags]
  red-o benchmark quality run [-runs 1] [-output benchmark-results/quality-synthetic]
  red-o benchmark quality evaluate -manifest trials.json -events events.jsonl -alerts alerts.jsonl [-strict-attribution=true]
  red-o benchmark quality compare -context-policy configs/context-policy.example.json -manifest trials.json -events events.jsonl -alerts alerts.jsonl

Prerequisites: Kubernetes + Tetragon for Detector; ClickHouse for Ingester and historical Web queries.
Web: http://127.0.0.1:8088; setup creates admin account with a fresh per-VM password in private .env.
Optional remote bind: red-o up -web-listen 0.0.0.0:8088 (use TLS/VPN; HTTP Basic Auth is not encrypted).
Without ClickHouse, Web can display recent JSONL events and alerts; not the historical database.
Events/alerts JSONL rotates at 64 MiB (max 32 queued segments; fail closed).
Raw telemetry has independent retention: 24h, 32 segments and 2 GiB budget by default.
Metrics history persists to ClickHouse for 30 days.
Detector, Ingester and Web start launch detached processes with separate PID/log files under data/.
Ingester exclusively owns ClickHouse imports; Web can use ClickHouse or a bounded read-only JSONL fallback.
Keep data/web-offsets.json from previous versions when upgrading (legacy checkpoint name).
The three "run" commands stay in foreground (Ctrl+C to stop).`))
}

func qualityCommand(args []string) int {
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = os.Chdir(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: red-o benchmark quality run|evaluate|compare [flags]")
		return 2
	}
	mode := args[0]
	if mode != "run" && mode != "evaluate" && mode != "compare" {
		fmt.Fprintln(os.Stderr, "unknown quality mode:", mode)
		return 2
	}
	fs := flag.NewFlagSet("benchmark quality "+mode, flag.ContinueOnError)
	suite := fs.String("suite", "tests/fixtures/detection-quality/scenarios.json", "labelled seven-scenario suite")
	rules := fs.String("rules", "configs/rules.json", "rules configuration")
	corrs := fs.String("correlations", "configs/correlations.json", "correlation configuration")
	runs := fs.Int("runs", 1, "deterministic fixture repetitions (not independent trials)")
	defaultOutput := "benchmark-results/quality-live"
	if mode == "run" {
		defaultOutput = "benchmark-results/quality-synthetic"
	}
	if mode == "compare" {
		defaultOutput = "benchmark-results/quality-context-comparison"
	}
	output := fs.String("output", defaultOutput, "report directory")
	contextPolicy := fs.String("context-policy", "", "context triage policy JSON (required for compare)")
	manifest := fs.String("manifest", "", "manual ground truth trials JSON (evaluate only)")
	events := fs.String("events", "", "comma-separated JSONL file paths/globs (evaluate only)")
	alerts := fs.String("alerts", "", "comma-separated JSONL file paths/globs (evaluate only)")
	strict := fs.Bool("strict-attribution", true, "reject correlated alerts containing event IDs not assigned to the same trial (evaluate only)")
	if err = fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments", fs.Args())
		return 2
	}
	if mode == "compare" {
		if *runs != 1 || !*strict || *manifest == "" || *events == "" || *alerts == "" || *contextPolicy == "" {
			fmt.Fprintln(os.Stderr, "compare requires -context-policy, -manifest, -events, -alerts, strict-attribution=true and -runs 1")
			return 2
		}
		cmp, cmpErr := quality.CompareLive(quality.CompareOptions{
			Live:          quality.LiveOptions{Suite: *suite, Rules: *rules, Correlations: *corrs, Manifest: *manifest, Events: *events, Alerts: *alerts, StrictAttribution: true},
			ContextPolicy: *contextPolicy, Output: *output,
		})
		if cmpErr != nil {
			fmt.Fprintln(os.Stderr, "quality compare:", cmpErr)
			return 1
		}
		fmt.Printf("Context comparison: baseline TP=%d FP=%d FN=%d TN=%d F1=%.3f; contextual TP=%d FP=%d FN=%d TN=%d F1=%.3f; approved=%d (counterfactual only)\n", cmp.Baseline.TP, cmp.Baseline.FP, cmp.Baseline.FN, cmp.Baseline.TN, cmp.Baseline.F1, cmp.Contextual.TP, cmp.Contextual.FP, cmp.Contextual.FN, cmp.Contextual.TN, cmp.Contextual.F1, cmp.Approved)
		fmt.Println("Reports:", filepath.Join(*output, "comparison.json"), filepath.Join(*output, "comparison-trials.csv"), filepath.Join(*output, "triage-decisions.jsonl"))
		return 0
	}
	var report quality.Report
	if mode == "run" {
		report, err = quality.RunSynthetic(quality.RunOptions{Suite: *suite, Rules: *rules, Correlations: *corrs, Runs: *runs})
	} else {
		if *runs != 1 {
			fmt.Fprintln(os.Stderr, "-runs is only supported by run")
			return 2
		}
		if *manifest == "" || *events == "" || *alerts == "" {
			fmt.Fprintln(os.Stderr, "evaluate requires -manifest, -events and -alerts")
			return 2
		}
		report, err = quality.EvaluateLive(quality.LiveOptions{Suite: *suite, Rules: *rules, Correlations: *corrs, Manifest: *manifest, Events: *events, Alerts: *alerts, StrictAttribution: *strict})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "detection quality:", err)
		return 1
	}
	hashInputs := []string{*suite, *rules, *corrs}
	if mode == "evaluate" {
		hashInputs = append(hashInputs, *manifest)
	}
	if err = quality.AddHashes(&report, hashInputs...); err != nil {
		fmt.Fprintln(os.Stderr, "quality inputs:", err)
		return 1
	}
	if err = quality.Write(report, *output); err != nil {
		fmt.Fprintln(os.Stderr, "write quality:", err)
		return 1
	}
	fmt.Printf("Quality (%s): TP=%d FP=%d FN=%d TN=%d precision=%.3f recall=%.3f f1=%.3f\n", report.Kind, report.TP, report.FP, report.FN, report.TN, report.Precision, report.Recall, report.F1)
	if mode == "evaluate" {
		fmt.Printf("Coverage: observed=%d missing=%d partial=%d actions=%d; end-to-end positive recall=", report.Coverage.Observed, report.Coverage.Missing, report.Coverage.Partial, report.Coverage.Actions)
		if report.EndToEndRecall != nil {
			fmt.Printf("%.3f\n", *report.EndToEndRecall)
		} else {
			fmt.Println("NA")
		}
		if report.Latency.Samples > 0 {
			fmt.Printf("Action-to-alert latency: n=%d p50=%.2fms p95=%.2fms p99=%.2fms\n", report.Latency.Samples, *report.Latency.P50Ms, *report.Latency.P95Ms, *report.Latency.P99Ms)
		} else {
			fmt.Println("Action-to-alert latency: NA (no valid action_start and emitted_at pairs)")
		}
	}
	fmt.Println("Reports:", filepath.Join(*output, "quality.json"), filepath.Join(*output, "quality-summary.csv"), filepath.Join(*output, "quality-trials.csv"), filepath.Join(*output, "quality-latency.csv"))
	return 0
}
