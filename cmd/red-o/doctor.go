package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"runtime-detector/internal/autosetup"
	"runtime-detector/internal/contextpolicy"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/multisensor"
	"runtime-detector/internal/quality"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass, warn, fail
	Detail string `json:"detail"`
}
type doctorReport struct {
	Version  string        `json:"version"`
	Root     string        `json:"project_root"`
	Checks   []doctorCheck `json:"checks"`
	Passed   int           `json:"passed"`
	Warnings int           `json:"warnings"`
	Failed   int           `json:"failed"`
	Ready    bool          `json:"ready"`
}

func (r *doctorReport) add(name, status, detail string) {
	r.Checks = append(r.Checks, doctorCheck{name, status, detail})
	switch status {
	case "pass":
		r.Passed++
	case "warn":
		r.Warnings++
	case "fail":
		r.Failed++
	}
}
func checkErr(r *doctorReport, name string, err error, info string) {
	if err != nil {
		r.add(name, "fail", err.Error())
	} else {
		r.add(name, "pass", info)
	}
}
func kubeCommand(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	kubectl := "kubectl"
	if _, err := exec.LookPath(kubectl); err != nil {
		if _, err = exec.LookPath("k3s"); err != nil {
			return "", fmt.Errorf("neither kubectl nor k3s found in PATH")
		}
		kubectl = "k3s"
		args = append([]string{"kubectl"}, args...)
	}
	cmd := exec.CommandContext(ctx, kubectl, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		// Kubernetes provider errors are not treated as shell commands or credentials.
		detail := strings.TrimSpace(string(b))
		if len(detail) > 250 {
			detail = detail[:250]
		}
		return "", fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, detail)
	}
	return strings.TrimSpace(string(b)), nil
}

// read-only diagnostic: never creates namespaces, changes policies, starts
// containers, writes data/ or modifies cluster configuration.
func collectDoctor(root, sensorsFile, policyFile string, requireSensors, kubernetes, clickhouse bool) doctorReport {
	out := doctorReport{Version: releaseVersion, Root: root}
	if runtime.GOOS != "linux" {
		out.add("platform", "warn", "K3s/Tetragon deployment requires Linux; offline analysis is cross-platform")
	} else {
		out.add("platform", "pass", runtime.GOOS+"/"+runtime.GOARCH)
	}
	rules, err := detection.Load(filepath.Join(root, "configs/rules.json"))
	if err != nil {
		checkErr(&out, "rules", err, "")
	} else {
		enabled := 0
		for _, r := range rules.Rules {
			if r.Enabled {
				enabled++
			}
		}
		out.add("rules", "pass", fmt.Sprintf("%d rules, %d enabled", len(rules.Rules), enabled))
	}
	corrs, err := correlation.Load(filepath.Join(root, "configs/correlations.json"))
	if err != nil {
		checkErr(&out, "correlations", err, "")
	} else {
		out.add("correlations", "pass", fmt.Sprintf("%d correlation rules", len(corrs.Rules)))
	}
	_, err = quality.RunSynthetic(quality.RunOptions{
		Suite:        filepath.Join(root, "tests/fixtures/detection-quality/scenarios.json"),
		Rules:        filepath.Join(root, "configs/rules.json"),
		Correlations: filepath.Join(root, "configs/correlations.json"), Runs: 1,
	})
	checkErr(&out, "seven-scenario-suite", err, "seven-scenario fixture is valid; offline only")

	policyPath := filepath.Join(root, "deployments/tracing-policies/serviceaccount-token.yaml")
	body, err := os.ReadFile(policyPath)
	if err == nil {
		for _, prefix := range []string{"/run/secrets/kubernetes.io/serviceaccount/", "/var/run/secrets/kubernetes.io/serviceaccount/"} {
			if !strings.Contains(string(body), prefix) {
				err = fmt.Errorf("TracingPolicy lacks %s; token reads can be missed", prefix)
				break
			}
		}
	}
	checkErr(&out, "serviceaccount-tracingpolicy", err, "both /run and /var/run token path prefixes present; deployment not verified")

	if sensorsFile == "" {
		p := filepath.Join(root, "configs/sensors.json")
		if _, err := os.Stat(p); err == nil {
			sensorsFile = p
		}
	}
	if sensorsFile == "" {
		status := "warn"
		if requireSensors {
			status = "fail"
		}
		out.add("sensors", status, "configs/sensors.json absent; specify -sensors path for multi-sensor deployment")
	} else {
		conf, err := multisensor.Load(sensorsFile)
		if err != nil {
			checkErr(&out, "sensors", err, "")
		} else {
			var ids []string
			for _, s := range conf.Sensors {
				ids = append(ids, s.ID+":"+s.Type)
			}
			out.add("sensors", "pass", fmt.Sprintf("%d validated sources (%s); backend availability not checked", len(conf.Sensors), strings.Join(ids, ", ")))
		}
	}
	if policyFile != "" {
		policy, err := contextpolicy.Load(policyFile)
		if err != nil {
			checkErr(&out, "context-policy", err, "")
		} else {
			active := 0
			for _, p := range policy.Policies {
				if p.Enabled {
					active++
				}
			}
			out.add("context-policy", "pass", fmt.Sprintf("%d policies, %d enabled; approval provenance not independently verified", len(policy.Policies), active))
		}
	} else {
		out.add("context-policy", "warn", "advisory context disabled; pass -context-policy to validate a local policy")
	}
	if st, err := os.Stat(filepath.Join(root, "data")); err == nil {
		if st.IsDir() {
			out.add("runtime-data", "pass", "data/ exists; read-only check, not a write/durability test")
		} else {
			out.add("runtime-data", "fail", "data exists but is not a directory")
		}
	} else if os.IsNotExist(err) {
		out.add("runtime-data", "warn", "data/ does not exist; offline benchmarks still work")
	} else {
		out.add("runtime-data", "fail", err.Error())
	}
	if kubernetes {
		if v, err := kubeCommand("config", "current-context"); err != nil {
			checkErr(&out, "kubectl-context", err, "")
		} else {
			out.add("kubectl-context", "pass", v)
		}
		_, err := kubeCommand("get", "namespace", "security-lab", "-o", "name")
		if err != nil {
			out.add("security-lab", "warn", "lab namespace absent; normal event collection is still available, but the seven-scenario fixtures use security-lab")
		} else {
			out.add("security-lab", "pass", "test namespace exists")
		}
		_, err = kubeCommand("get", "tracingpolicy", "red-o-serviceaccount-token", "-o", "name")
		if err != nil {
			out.add("cluster-token-policy", "warn", "token TracingPolicy missing; R010/R007 require that optional hook")
		} else {
			out.add("cluster-token-policy", "pass", "TracingPolicy installed (verify enabled with tetra tracingpolicy list)")
		}
		b, err := kubeCommand("get", "pods", "--all-namespaces", "-o", "json")
		if err != nil {
			checkErr(&out, "tetragon-pod", err, "")
		} else {
			pods, discoverErr := autosetup.ParseTetragonPods([]byte(b), "")
			if discoverErr != nil {
				checkErr(&out, "tetragon-pod", discoverErr, "")
			} else {
				out.add("tetragon-pod", "pass", fmt.Sprintf("%d Ready Tetragon Pod(s), excluding operator", len(pods)))
			}
		}
	} else {
		out.add("kubernetes", "warn", "live K3s/Tetragon not checked (use -kubernetes)")
	}
	if clickhouse {
		client := http.Client{Timeout: 4 * time.Second}
		response, err := client.Get("http://127.0.0.1:8123/ping")
		if err != nil {
			checkErr(&out, "clickhouse", err, "")
		} else {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				out.add("clickhouse", "pass", "local HTTP ping returned 200; no SQL insert/read tested")
			} else {
				out.add("clickhouse", "fail", fmt.Sprintf("local ping returned HTTP %d", response.StatusCode))
			}
		}
	} else {
		out.add("clickhouse", "warn", "local ClickHouse not checked (use -clickhouse)")
	}
	out.Ready = out.Failed == 0
	return out
}

func doctorCommand(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	sensors := fs.String("sensors", "", "path to local multi-sensor configuration; auto-detects configs/sensors.json")
	policy := fs.String("context-policy", "", "path to local advisory policy to validate")
	requireSensors := fs.Bool("require-sensors", false, "fail when multi-sensor configuration is absent")
	kubernetes := fs.Bool("kubernetes", false, "check live Kubernetes namespace, Tetragon Pod and token policy")
	clickhouse := fs.Bool("clickhouse", false, "check read-only local ClickHouse /ping")
	asJSON := fs.Bool("json", false, "output machine-readable JSON report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintln(os.Stderr, "doctor: unexpected arguments")
		return 2
	}
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctor:", err)
		return 1
	}
	// Match the same config-relative paths that the running Detector uses.
	if err := os.Chdir(root); err != nil {
		fmt.Fprintln(os.Stderr, "doctor:", err)
		return 1
	}
	report := collectDoctor(root, *sensors, *policy, *requireSensors, *kubernetes, *clickhouse)
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return 1
		}
	} else {
		fmt.Printf("RED-O v%s | read-only laboratory preflight | %s\n", report.Version, report.Root)
		for _, c := range report.Checks {
			fmt.Printf("%-5s %-26s %s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
		}
		fmt.Printf("Result: %d PASS / %d WARN / %d FAIL; ready=%t\n", report.Passed, report.Warnings, report.Failed, report.Ready)
		if report.Ready {
			fmt.Println("Readiness covers checked prerequisites only; live detector quality remains unverified.")
		}
	}
	if !report.Ready {
		return 1
	}
	return 0
}
