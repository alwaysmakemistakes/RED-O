package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"strings"
	"time"

	"runtime-detector/internal/autosetup"
)

// The local credential file never belongs in git or a release artifact.
const localCredentials = ".env"

func readLocalSettings() (map[string]string, error) {
	result := map[string]string{}
	st, err := os.Stat(localCredentials)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s contains secrets and must have permissions 0600 (chmod 600 %s)", localCredentials, localCredentials)
	}
	data, err := os.ReadFile(localCredentials)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed %s line (expected KEY=value)", localCredentials)
		}
		switch parts[0] {
		case "WEB_USER", "WEB_PASSWORD", "CH_PASSWORD", "CH_URL", "CH_USER":
			result[parts[0]] = parts[1]
		}
	}
	return result, nil
}
func loadLocalSettings() error {
	settings, err := readLocalSettings()
	if err != nil {
		return err
	}
	for k, v := range settings {
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
	return nil
}
func randomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err = f.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
func resolveLocalRoot() (string, error) {
	root, err := findProjectRoot()
	if err != nil {
		return "", err
	}
	if err = os.Chdir(root); err != nil {
		return "", err
	}
	return root, nil
}
func setupCommand(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	kube := fs.String("kubectl", "auto", "kubectl executable (auto uses kubectl or k3s kubectl)")
	namespace := fs.String("tetragon-namespace", "", "limit Tetragon discovery to namespace (default all)")
	kubeContext := fs.String("kube-context", "", "explicit kubeconfig context")
	cluster := fs.String("cluster", "", "sensor cluster ID (default sanitized kube context)")
	eventNS := fs.String("event-namespace", "", "filter Tetragon to one workload namespace (default all)")
	auditMode := fs.String("audit", "auto", "auto|off|required; local Kubernetes Audit log is optional")
	auditPath := fs.String("audit-path", "", "explicit readable local Kubernetes Audit log")
	force := fs.Bool("refresh-sensors", false, "refresh sensor config (backup existing file; leaves .env untouched)")
	demoCredentials := fs.Bool("demo-credentials", false, "opt in to admin/admin for LOOPBACK-ONLY lab demonstrations; NOT safe for remote")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "setup: unexpected arguments")
		return 2
	}
	if _, err := resolveLocalRoot(); err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		return 1
	}
	if err := os.MkdirAll("configs", 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll("data", 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sensorFile := "configs/sensors.json"
	_, statErr := os.Stat(sensorFile)
	refresh := *force || os.IsNotExist(statErr)
	if statErr != nil && !os.IsNotExist(statErr) {
		fmt.Fprintln(os.Stderr, statErr)
		return 1
	}
	if refresh {
		result, err := autosetup.Discover(context.Background(), autosetup.Options{Kubectl: *kube, Context: *kubeContext, Namespace: *namespace, Cluster: *cluster, EventNamespace: *eventNS, AuditPath: *auditPath, AuditMode: *auditMode})
		if err != nil {
			fmt.Fprintln(os.Stderr, "setup discovery:", err)
			return 1
		}
		data, err := autosetup.Encode(result.Config)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if *force && statErr == nil {
			backup := sensorFile + ".bak-" + time.Now().UTC().Format("20060102T150405Z")
			if err := os.Rename(sensorFile, backup); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Println("Previous sensor config backed up:", backup)
		}
		if err := writePrivate(sensorFile, append(data, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("Tetragon discovered: %d Ready Pod(s) across Kubernetes nodes; Kubernetes context=%s\n", len(result.Config.Sensors)-boolInt(result.AuditIncluded), result.KubernetesContext)
		for _, s := range result.Config.Sensors {
			fmt.Printf("  %s: %s (node=%s pod=%s path=%s)\n", s.ID, s.Type, s.Node, s.Pod, s.Path)
		}
		for _, n := range result.Notices {
			fmt.Println("NOTICE:", n)
		}
	} else {
		fmt.Println("Keeping existing", sensorFile, "(use -refresh-sensors for explicit rediscovery)")
	}
	if _, err := os.Stat(localCredentials); errors.Is(err, os.ErrNotExist) {
		pass, err := randomPassword()
		if *demoCredentials {
			pass = "admin"
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		chPass := os.Getenv("CH_PASSWORD")
		if chPass == "" {
			chPass = defaultCHPassword
		}
		settings := fmt.Sprintf("# RED-O private local settings; generated by setup. Never commit this file.\nWEB_USER=admin\nWEB_PASSWORD=%s\nCH_PASSWORD=%s\n", pass, chPass)
		if err := writePrivate(localCredentials, []byte(settings)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("Web initial credentials: admin / %s\n", pass)
		fmt.Println("Saved to private .env (0600). View later with: red-o credentials")
		if *demoCredentials {
			fmt.Println("SECURITY WARNING: demo credentials admin/admin allowed only on localhost; rotate before remote access.")
		}
	} else if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	} else {
		fmt.Println("Keeping existing private .env credentials")
	}
	fmt.Println("Setup complete. Next: ./bin/red-o up")
	return 0
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func credentialsCommand(args []string) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != "rotate" && args[0] != "show") {
		fmt.Fprintln(os.Stderr, "usage: red-o credentials [show|rotate]")
		return 2
	}
	if _, err := resolveLocalRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	settings, err := readLocalSettings()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if settings["WEB_PASSWORD"] == "" {
		fmt.Fprintln(os.Stderr, "no credentials; run red-o setup")
		return 1
	}
	if len(args) == 1 && args[0] == "rotate" {
		pass, err := randomPassword()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		settings["WEB_PASSWORD"] = pass
		data := fmt.Sprintf("WEB_USER=%s\nWEB_PASSWORD=%s\nCH_PASSWORD=%s\n", settings["WEB_USER"], pass, settings["CH_PASSWORD"])
		if x := settings["CH_URL"]; x != "" {
			data += "CH_URL=" + x + "\n"
		}
		if x := settings["CH_USER"]; x != "" {
			data += "CH_USER=" + x + "\n"
		}
		backup := localCredentials + ".bak-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(localCredentials, backup); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := writePrivate(localCredentials, []byte(data)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("New credentials: %s / %s\n", settings["WEB_USER"], pass)
		fmt.Println("Restart Web to apply: red-o web stop && red-o web start")
		return 0
	}
	fmt.Printf("Web credentials: %s / %s\n", settings["WEB_USER"], settings["WEB_PASSWORD"])
	fmt.Println("Do not paste these secrets into public logs. Use 'red-o credentials rotate' to change password.")
	return 0
}

func hasClickHouse() bool {
	url := os.Getenv("CH_URL")
	if url == "" {
		url = "http://127.0.0.1:8123"
	}
	url = strings.TrimRight(url, "/") + "/?query=SELECT%201"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	user := os.Getenv("CH_USER")
	if user == "" {
		user = "default"
	}
	req.SetBasicAuth(user, os.Getenv("CH_PASSWORD"))
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
func componentRunning(component string) bool {
	var pid int
	var err error
	switch component {
	case "detector":
		pid, err = readDetectorPID()
		return err == nil && isDetectorChild(pid)
	case "web":
		pid, err = readWebPID()
		return err == nil && isWebChild(pid)
	case "ingester":
		pid, err = readIngesterPID()
		return err == nil && isIngesterChild(pid)
	}
	return false
}
func upCommand(args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	listen := fs.String("web-listen", "127.0.0.1:8088", "Web binding (use 0.0.0.0:8088 for explicitly trusted/private networks only)")
	storage := fs.String("storage", "auto", "auto|jsonl|clickhouse")
	eventNS := fs.String("event-namespace", "", "Tetragon event namespace used only on first setup; default all")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "up: unexpected arguments")
		return 2
	}
	if *storage != "auto" && *storage != "clickhouse" && *storage != "jsonl" {
		fmt.Fprintln(os.Stderr, "storage must be auto|clickhouse|jsonl")
		return 2
	}
	if _, err := resolveLocalRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll("data", 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, file := range []string{"configs/sensors.json", ".env"} {
		if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
			if code := setupCommand([]string{"-event-namespace", *eventNS}); code != 0 {
				return code
			}
			break
		} else if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if err := loadLocalSettings(); err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		return 1
	}
	webStorage := *storage
	if webStorage == "auto" {
		if hasClickHouse() {
			webStorage = "clickhouse"
		} else {
			webStorage = "jsonl"
		}
	}
	if webStorage == "clickhouse" && !hasClickHouse() {
		fmt.Fprintln(os.Stderr, "ClickHouse unavailable or authentication failed; use -storage jsonl or auto")
		return 1
	}
	if componentRunning("detector") {
		fmt.Println("Detector already running")
	} else if err := startDetectorInBackground([]string{"-source", "multi", "-sensors", "configs/sensors.json", "-mode", "forensic", "-sensor-lateness", "2s", "-sensor-idle-timeout", "4s", "-sensor-buffer", "8192"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if webStorage == "clickhouse" {
		if componentRunning("ingester") {
			fmt.Println("Ingester already running")
		} else {
			opts := []string{}
			if url := os.Getenv("CH_URL"); url != "" {
				opts = append(opts, "-clickhouse", url)
			}
			if user := os.Getenv("CH_USER"); user != "" {
				opts = append(opts, "-ch-user", user)
			}
			if err := startIngesterInBackground(opts); err != nil {
				fmt.Fprintln(os.Stderr, "ingester:", err)
				return 1
			}
		}
	} else {
		fmt.Println("JSONL-only mode: ClickHouse/Ingester not required; showing recent local events and alerts. Historical metrics and database features are unavailable.")
	}
	if componentRunning("web") {
		fmt.Println("Web already running; restart Web to change listen/storage settings")
	} else {
		opts := []string{"-listen", *listen, "-storage", webStorage}
		if url := os.Getenv("CH_URL"); url != "" {
			opts = append(opts, "-clickhouse", url)
		}
		if user := os.Getenv("CH_USER"); user != "" {
			opts = append(opts, "-ch-user", user)
		}
		if err := startWebInBackground(opts); err != nil {
			fmt.Fprintln(os.Stderr, "web:", err)
			return 1
		}
	}
	host, port, err := net.SplitHostPort(*listen)
	if err == nil && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		fmt.Fprintln(os.Stderr, "SECURITY WARNING: HTTP Basic Auth over an unencrypted network is unsafe. Restrict access to trusted networks and use TLS reverse proxy/VPN.")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Warning: invalid listen address:", err)
	} else {
		fmt.Printf("Web: http://127.0.0.1:%s/ (SSH tunnel for remote viewing; configured bind=%s)\n", port, *listen)
	}
	fmt.Println("Web username: admin; initial password was generated during setup. See: ./bin/red-o credentials")
	fmt.Printf("Storage mode: %s; Audit sensor is optional and needed for API-only rules such as R016.\n", webStorage)
	return 0
}
func downCommand(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: red-o down")
		return 2
	}
	if _, err := resolveLocalRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, x := range []struct {
		name    string
		running bool
		stop    func() error
	}{{"web", componentRunning("web"), stopWeb}, {"ingester", componentRunning("ingester"), stopIngester}, {"detector", componentRunning("detector"), stopDetector}} {
		if x.running {
			if err := x.stop(); err != nil {
				fmt.Fprintln(os.Stderr, x.name, err)
				return 1
			}
		}
	}
	return 0
}
func allStatusCommand(args []string) int {
	if len(args) != 0 {
		return 2
	}
	if _, err := resolveLocalRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, name := range []string{"detector", "web", "ingester"} {
		fmt.Printf("%s: ", name)
		if componentRunning(name) {
			fmt.Println("running")
		} else {
			fmt.Println("stopped")
		}
	}
	return 0
}

// isRemoteDemoCredentials rejects the publicly known demo password on any
// bind target that is not strictly loopback. A named host is not treated as
// loopback unless it is exactly localhost.
func isRemoteDemoCredentials(addr, user, pass string) bool {
	if user != "admin" || pass != "admin" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
