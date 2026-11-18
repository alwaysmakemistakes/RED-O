package benchmark

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func opts() Options {
	return Options{Runs: 2, Lateness: 2 * time.Second, Buffer: 256, RulesFile: "../../configs/rules.json", CorrelationsFile: "../../configs/correlations.json"}
}
func TestLabelledScenariosAgainstRealRules(t *testing.T) {
	r, err := Run(opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Scenarios) != 13 {
		t.Fatalf("scenarios = %d", len(r.Scenarios))
	}
	if r.FP != 0 || r.FN != 0 || r.TP == 0 {
		t.Fatalf("unexpected mismatch tp=%d fp=%d fn=%d", r.TP, r.FP, r.FN)
	}
	if r.Precision != 1 || r.Recall != 1 || r.F1 != 1 {
		t.Fatalf("scores %+v", r)
	}
	found := false
	for _, s := range r.Scenarios {
		if s.Name == "duplicate-token-one-network" {
			found = true
			if s.Observed["R007"] != 2 {
				t.Fatalf("duplicate token generated %v", s.Observed)
			}
		}
	}
	if !found {
		t.Fatal("missing dedup scenario")
	}
}
func TestReportFilesAndValidation(t *testing.T) {
	o := opts()
	o.Runs = 0
	if _, err := Run(o); err == nil {
		t.Fatal("expected validation failure")
	}
	r, err := Run(opts())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	jsonPath, csvPath := filepath.Join(dir, "report.json"), filepath.Join(dir, "scenarios.csv")
	if err := Write(r, jsonPath, csvPath); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Report
	if err = json.Unmarshal(b, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.TP != r.TP {
		t.Fatal("JSON report mismatch")
	}
	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 14 {
		t.Fatalf("CSV rows=%d", len(records))
	}
}
