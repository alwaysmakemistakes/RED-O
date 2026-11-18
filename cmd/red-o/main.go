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
	defaults := []string{"-listen", "127.0.0.1:8088", "-clickhouse", "http://127.0.0.1:8123", "-exceptions", "data/exceptions.json", "-heartbeat", "data/collector-heartbeat.json", "-detector-metrics", "http://127.0.0.1:9095/metrics"}
	fmt.Println("RED-O Web running in foreground (Ctrl+C to stop)")
	webapp.Run(append(defaults, args...))
}

func runIngesterForeground(args []string) error {
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
  red-o detector start [detector flags]   # background; returns terminal
  red-o detector stop | status | logs
  red-o detector run [detector flags]     # foreground
  red-o ingester start [ingester flags]  # background; imports JSONL + persists metrics
  red-o ingester stop | status | logs
  red-o ingester run [ingester flags]    # foreground
  red-o web start [web flags]        # background; returns terminal
  red-o web stop | status | logs
  red-o web run [web flags]          # foreground
  red-o benchmark run [-runs 20] [-output benchmark-results]
  red-o benchmark performance load|sweep|latency [flags]

Prerequisites: Kubernetes + Tetragon for Detector; ClickHouse for Ingester and historical Web queries.
Web: http://127.0.0.1:8088; demo credentials admin/admin (localhost only).
Set WEB_USER, WEB_PASSWORD, CH_PASSWORD for deployment.
Events/alerts JSONL rotates at 64 MiB (max 32 queued segments; fail closed).
Raw telemetry has independent retention: 24h, 32 segments and 2 GiB budget by default.
Metrics history persists to ClickHouse for 30 days.
Detector, Ingester and Web start launch detached processes with separate PID/log files under data/.
Ingester exclusively owns JSONL import and metrics history writes; Web only queries ClickHouse.
Keep data/web-offsets.json from previous versions when upgrading (legacy checkpoint name).
The three "run" commands stay in foreground (Ctrl+C to stop).`))
}
