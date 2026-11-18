package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Endpoint, User, Password string
	HTTP                     *http.Client
}

func New(endpoint, user, password string) *Client {
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), User: user, Password: password, HTTP: &http.Client{Timeout: 15 * time.Second}}
}
func (c *Client) Query(ctx context.Context, query string, params map[string]string) ([]map[string]any, error) {
	body, err := c.Do(ctx, query, nil, params)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(body))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (c *Client) Do(ctx context.Context, sql string, data []byte, params map[string]string) ([]byte, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("query", sql)
	q.Set("wait_end_of_query", "1")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Password)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("clickhouse: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}
func (c *Client) Init(ctx context.Context) error {
	queries := []string{
		`CREATE DATABASE IF NOT EXISTS runtime_security`,
		`CREATE TABLE IF NOT EXISTS runtime_security.events (event_id String, timestamp String, event_type LowCardinality(String), namespace LowCardinality(String), pod String, process_binary String, file_path String, destination_ip String, payload String, ingested_at DateTime DEFAULT now()) ENGINE=ReplacingMergeTree(ingested_at) ORDER BY event_id`,
		`CREATE TABLE IF NOT EXISTS runtime_security.alerts (alert_id String, timestamp String, rule_id LowCardinality(String), severity LowCardinality(String), namespace LowCardinality(String), pod String, payload String, ingested_at DateTime DEFAULT now()) ENGINE=ReplacingMergeTree(ingested_at) ORDER BY alert_id`,
		`CREATE TABLE IF NOT EXISTS runtime_security.detector_metrics (instance LowCardinality(String), observed_at DateTime64(3, 'UTC'), payload String) ENGINE=MergeTree ORDER BY (instance, observed_at) TTL observed_at + INTERVAL 30 DAY`,
	}
	for _, q := range queries {
		if _, err := c.Do(ctx, q, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) Insert(ctx context.Context, kind string, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	var table string
	switch kind {
	case "events":
		table = "runtime_security.events"
	case "alerts":
		table = "runtime_security.alerts"
	default:
		return fmt.Errorf("unknown stream")
	}
	var b bytes.Buffer
	for _, r := range rows {
		j, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	_, err := c.Do(ctx, "INSERT INTO "+table+" FORMAT JSONEachRow", b.Bytes(), nil)
	return err
}

// StoreMetrics persists a single bounded metric snapshot. Failure must not affect the detector.
func (c *Client) StoreMetrics(ctx context.Context, instance string, observed time.Time, payload []byte) error {
	if !json.Valid(payload) {
		return fmt.Errorf("invalid metrics JSON")
	}
	row, err := json.Marshal(map[string]any{"instance": instance, "observed_at": observed.UTC().Format("2006-01-02 15:04:05.000"), "payload": string(payload)})
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, "INSERT INTO runtime_security.detector_metrics FORMAT JSONEachRow", append(row, '\n'), nil)
	return err
}

// MetricsHistory returns at most 720 representative points over a fixed, validated time range.
func (c *Client) MetricsHistory(ctx context.Context, instance, window string) ([]map[string]any, error) {
	var interval, step string
	switch window {
	case "10m":
		interval, step = "10 MINUTE", "5"
	case "1h":
		interval, step = "1 HOUR", "5"
	case "24h":
		interval, step = "24 HOUR", "120"
	default:
		return nil, fmt.Errorf("unsupported metrics window")
	}
	q := `SELECT formatDateTime(bucket, '%Y-%m-%dT%H:%i:%S', 'UTC') AS at, argMax(payload, observed_at) AS payload FROM (SELECT toStartOfInterval(observed_at, INTERVAL ` + step + ` SECOND) AS bucket, observed_at, payload FROM runtime_security.detector_metrics WHERE instance={instance:String} AND observed_at >= now() - INTERVAL ` + interval + `) GROUP BY bucket ORDER BY bucket DESC LIMIT 720 FORMAT JSONEachRow`
	rows, err := c.Query(ctx, q, map[string]string{"instance": instance})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows, nil
}
