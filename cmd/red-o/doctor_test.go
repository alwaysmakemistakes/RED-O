package main

import (
	"os"
	"path/filepath"
	"testing"
)

func findDoctorCheck(r doctorReport, name string) (doctorCheck, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return doctorCheck{}, false
}
func TestDoctorOfflineAndSensors(t *testing.T) {
	root, err := findProjectRoot()
	if err != nil {
		t.Fatal(err)
	}
	r := collectDoctor(root, "", "", false, false, false)
	if r.Failed != 0 || !r.Ready {
		t.Fatalf("offline preflight failed: %+v", r)
	}
	if got, _ := findDoctorCheck(r, "seven-scenario-suite"); got.Status != "pass" {
		t.Fatalf("fixture suite not validated: %+v", got)
	}
	if got, _ := findDoctorCheck(r, "serviceaccount-tracingpolicy"); got.Status != "pass" {
		t.Fatalf("token prefixes not validated: %+v", got)
	}
	d := t.TempDir()
	file := filepath.Join(d, "invalid-sensors.json")
	if err := os.WriteFile(file, []byte(`{"schema_version":"1.0","sensors":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	r = collectDoctor(root, file, "", false, false, false)
	if got, _ := findDoctorCheck(r, "sensors"); got.Status != "fail" {
		t.Fatalf("invalid sensors passed: %+v", got)
	}
	if r.Ready {
		t.Fatal("invalid sensors marked ready")
	}
	r = collectDoctor(root, filepath.Join(d, "absent.json"), "", true, false, false)
	if r.Ready {
		t.Fatal("missing required sensors marked ready")
	}
}
func TestDoctorInvalidPolicyFailsClosed(t *testing.T) {
	root, err := findProjectRoot()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bad-policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1.0","policies":[{"id":"bad","decision":"approved"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := collectDoctor(root, "", path, false, false, false)
	if r.Ready {
		t.Fatalf("invalid context policy marked ready: %+v", r)
	}
}
