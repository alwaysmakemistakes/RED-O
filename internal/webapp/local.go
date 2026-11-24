package webapp

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// JSONL mode is a zero-dependency, bounded recent-data viewer. It deliberately
// does not claim ClickHouse's historical querying, deduplication or retention.
// Only the newest 64 MiB of each active JSONL file is read per request.
const localReadCap int64 = 64 << 20
const localMaxRecords = 10000

type localRecord struct {
	Raw    json.RawMessage
	Fields map[string]any
}

func localRecords(path string) ([]localRecord, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []localRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > localReadCap {
		if _, err = f.Seek(st.Size()-localReadCap, io.SeekStart); err != nil {
			return nil, err
		}
		// Skip incomplete first record, if we start in the middle of a line.
		b := bufio.NewReader(f)
		_, _ = b.ReadBytes('\n')
		return readLocalLines(b)
	}
	return readLocalLines(f)
}
func readLocalLines(rd io.Reader) ([]localRecord, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	result := make([]localRecord, 0, 256)
	for sc.Scan() {
		b := sc.Bytes()
		if !json.Valid(b) {
			continue
		}
		var fields map[string]any
		if json.Unmarshal(b, &fields) != nil {
			continue
		}
		result = append(result, localRecord{Raw: append([]byte(nil), b...), Fields: fields})
		if len(result) > localMaxRecords {
			copy(result, result[1:])
			result = result[:localMaxRecords]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
func jsonPath(fields map[string]any, path ...string) string {
	var x any = fields
	for _, part := range path {
		m, ok := x.(map[string]any)
		if !ok {
			return ""
		}
		x = m[part]
	}
	return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.TrimSpace(toString(x)), "\n", " "), "\""))
}
func toString(v any) string {
	if v == nil {
		return ""
	}
	if x, ok := v.(string); ok {
		return x
	}
	return ""
}

func localList(w http.ResponseWriter, r *http.Request, path string, isAlert bool) {
	records, err := localRecords(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	namespace := r.URL.Query().Get("namespace")
	nameFilter := r.URL.Query().Get("type")
	if isAlert {
		nameFilter = r.URL.Query().Get("rule")
	}
	severity := r.URL.Query().Get("severity")
	matched := make([]localRecord, 0, len(records))
	for _, rec := range records {
		if namespace != "" && jsonPath(rec.Fields, "kubernetes", "namespace") != namespace {
			continue
		}
		if nameFilter != "" {
			key := "event_type"
			if isAlert {
				key = "rule_id"
			}
			if jsonPath(rec.Fields, key) != nameFilter {
				continue
			}
		}
		if isAlert && severity != "" && jsonPath(rec.Fields, "severity") != severity {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(string(rec.Raw)), q) {
			continue
		}
		matched = append(matched, rec)
	}
	key := r.URL.Query().Get("sort")
	valid := map[string]bool{"timestamp": true, "rule_id": isAlert, "severity": isAlert, "event_type": !isAlert, "process": !isAlert, "file_path": !isAlert, "destination_ip": !isAlert}
	if !valid[key] {
		key = "timestamp"
	}
	extract := func(m map[string]any) string {
		switch key {
		case "process":
			return jsonPath(m, "process", "binary")
		case "file_path":
			return jsonPath(m, "file", "path")
		case "destination_ip":
			return jsonPath(m, "network", "destination_ip")
		default:
			return jsonPath(m, key)
		}
	}
	desc := r.URL.Query().Get("dir") != "asc"
	sort.SliceStable(matched, func(i, j int) bool {
		a, b := extract(matched[i].Fields), extract(matched[j].Fields)
		if a == b {
			a = jsonPath(matched[i].Fields, "timestamp")
			b = jsonPath(matched[j].Fields, "timestamp")
		}
		if desc {
			return a > b
		}
		return a < b
	})
	n := safeLimit(r)
	if len(matched) > n {
		matched = matched[:n]
	}
	out := make([]json.RawMessage, 0, len(matched))
	for _, rec := range matched {
		out = append(out, rec.Raw)
	}
	write(w, out)
}
func localDetail(w http.ResponseWriter, r *http.Request, alertPath, eventPath string) {
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if len(id) > 128 || id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	alerts, err := localRecords(alertPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var alert map[string]any
	for i := len(alerts) - 1; i >= 0; i-- {
		if jsonPath(alerts[i].Fields, "alert_id") == id {
			alert = alerts[i].Fields
			break
		}
	}
	if alert == nil {
		http.NotFound(w, r)
		return
	}
	rawEvents, err := localRecords(eventPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	wanted := map[string]bool{}
	if ids, ok := alert["related_event_ids"].([]any); ok {
		for _, id := range ids {
			if text, ok := id.(string); ok {
				wanted[text] = true
			}
		}
	}
	related := make([]json.RawMessage, 0, len(wanted))
	for _, event := range rawEvents {
		if wanted[jsonPath(event.Fields, "event_id")] {
			related = append(related, event.Raw)
		}
	}
	write(w, map[string]any{"alert": alert, "events": related})
}
func localAgents(w http.ResponseWriter, r *http.Request, path string) {
	records, err := localRecords(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	type data struct {
		count            int
		last             string
		namespaces, pods map[string]bool
	}
	groups := map[string]*data{}
	for _, rec := range records {
		node := jsonPath(rec.Fields, "node")
		if node == "" {
			node = jsonPath(rec.Fields, "sensor", "node")
		}
		if node == "" {
			continue
		}
		d := groups[node]
		if d == nil {
			d = &data{namespaces: map[string]bool{}, pods: map[string]bool{}}
			groups[node] = d
		}
		d.count++
		if ts := jsonPath(rec.Fields, "timestamp"); ts > d.last {
			d.last = ts
		}
		if ns := jsonPath(rec.Fields, "kubernetes", "namespace"); ns != "" {
			d.namespaces[ns] = true
		}
		if pod := jsonPath(rec.Fields, "kubernetes", "pod"); pod != "" {
			d.pods[pod] = true
		}
	}
	out := make([]map[string]any, 0, len(groups))
	for node, d := range groups {
		out = append(out, map[string]any{"node": node, "events": d.count, "last_seen": d.last, "namespaces": len(d.namespaces), "pods": len(d.pods), "status": "observed_recent_jsonl", "detail": "Recent JSONL only; not a Kubernetes readiness check"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["node"].(string) < out[j]["node"].(string) })
	write(w, map[string]any{"health_available": false, "agents": out, "checked_at": "", "storage": "jsonl", "recent_limit": strconv.Itoa(localMaxRecords)})
}
