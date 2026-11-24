package detection

import (
	"fmt"
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestR021EvidenceChainAndWindow(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "R021", Name: "five", Enabled: true, Severity: "medium", EventType: "network.connect", DestinationCIDRs: []string{"10.0.0.0/8"}, DistinctDestinations: 5, WindowSeconds: 30}}}
	en, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	base := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	var alert model.SecurityAlert
	for i := 0; i < 5; i++ {
		ev := model.SecurityEvent{EventID: fmt.Sprintf("ev-%d", i), EventType: "network.connect", Timestamp: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano), Kubernetes: &model.Kubernetes{ContainerID: "cid", PodUID: "pod"}, Network: &model.Network{DestinationIP: fmt.Sprintf("10.43.1.%d", i+1)}}
		alerts, err := en.Evaluate(ev)
		if err != nil {
			t.Fatal(err)
		}
		if i < 4 && len(alerts) > 0 {
			t.Fatalf("early R021 at %d", i)
		}
		if i == 4 {
			if len(alerts) != 1 {
				t.Fatalf("missing R021: %+v", alerts)
			}
			alert = alerts[0]
		}
	}
	if alert.Evidence == nil || len(alert.Evidence.DestinationIPs) != 5 || len(alert.RelatedEventIDs) != 5 || alert.Evidence.Threshold != 5 {
		t.Fatalf("missing full evidence: %+v", alert)
	}
	for i, id := range alert.RelatedEventIDs {
		if id != fmt.Sprintf("ev-%d", i) {
			t.Fatalf("wrong evidence chain: %+v", alert.RelatedEventIDs)
		}
	}
	if alert.DetectedAt == "" {
		t.Fatal("no detected_at")
	}
}
