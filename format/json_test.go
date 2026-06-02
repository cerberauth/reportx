package format_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/internal/testdata"
)

func TestJSONMetadata(t *testing.T) {
	r := fullReport()
	data, err := format.NewJSONFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	meta := out["metadata"].(map[string]any)
	if meta["title"] != "Test Report" {
		t.Errorf("metadata.title = %v", meta["title"])
	}
	if meta["tool"] != "TestScanner" {
		t.Errorf("metadata.tool = %v", meta["tool"])
	}
	if meta["version"] != "1.0.0" {
		t.Errorf("metadata.version = %v", meta["version"])
	}
	if meta["target"] != "https://api.example.com" {
		t.Errorf("metadata.target = %v", meta["target"])
	}
	if meta["scan_date"] != "2024-01-15T12:00:00Z" {
		t.Errorf("metadata.scan_date = %v", meta["scan_date"])
	}
	if total := int(meta["total"].(float64)); total != len(testdata.Fixtures()) {
		t.Errorf("metadata.total = %d, want %d", total, len(testdata.Fixtures()))
	}
}

func TestJSONMetadataBySeverity(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
			{Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
			{Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
			{Severity: reportx.SeverityLow, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewJSONFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	meta := out["metadata"].(map[string]any)
	bySev := meta["by_severity"].(map[string]any)

	if bySev["critical"] != float64(2) {
		t.Errorf("by_severity.critical = %v, want 2", bySev["critical"])
	}
	if bySev["high"] != float64(1) {
		t.Errorf("by_severity.high = %v, want 1", bySev["high"])
	}
	if bySev["low"] != float64(1) {
		t.Errorf("by_severity.low = %v, want 1", bySev["low"])
	}
}

func TestJSONFindingFields(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, err := format.NewJSONFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)
	f := out["findings"].([]any)[0].(map[string]any)

	checks := map[string]any{
		"id":               "rich-1",
		"title":            "Rich Finding",
		"severity":         "critical",
		"cvss31_score":     float64(9.8),
		"cvss40_score":     float64(9.3),
		"cwe_id":           "CWE-89",
		"cwe_name":         "Improper Neutralization of Special Elements used in an SQL Command",
		"owasp_top10":      "A03:2021 – Injection",
		"url":              "https://api.example.com/users",
		"parameter":        "id",
		"description":      "SQL injection via the id parameter.",
		"remediation":      "Use parameterized queries.",
		"status":           "active",
		"fingerprint_hash": "abc123",
	}
	for key, want := range checks {
		if f[key] != want {
			t.Errorf("finding.%s = %v, want %v", key, f[key], want)
		}
	}

	tags := f["tags"].([]any)
	if len(tags) != 2 || tags[0] != "injection" || tags[1] != "sql" {
		t.Errorf("finding.tags = %v", tags)
	}

	extra := f["extra"].(map[string]any)
	if extra["scanner"] != "zap" {
		t.Errorf("finding.extra.scanner = %v", extra["scanner"])
	}

	ev := f["evidence"].(map[string]any)
	if ev["raw_request"] != "GET /users?id=1' HTTP/1.1" {
		t.Errorf("finding.evidence.raw_request = %v", ev["raw_request"])
	}
	if ev["raw_response"] != "HTTP/1.1 500 Internal Server Error" {
		t.Errorf("finding.evidence.raw_response = %v", ev["raw_response"])
	}
}

func TestJSONFindingTimestamps(t *testing.T) {
	ts := time.Date(2024, 3, 10, 8, 0, 0, 0, time.UTC)
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "t1", Title: "T", Severity: reportx.SeverityLow, Status: reportx.StatusActive,
			FirstSeen: ts, LastSeen: ts.Add(24 * time.Hour),
		}},
	}
	data, _ := format.NewJSONFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	f := out["findings"].([]any)[0].(map[string]any)

	if f["first_seen"] != "2024-03-10T08:00:00Z" {
		t.Errorf("first_seen = %v", f["first_seen"])
	}
	if f["last_seen"] != "2024-03-11T08:00:00Z" {
		t.Errorf("last_seen = %v", f["last_seen"])
	}
}

func TestJSONFindingTimestampsOmittedWhenZero(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewJSONFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	f := out["findings"].([]any)[0].(map[string]any)

	if _, ok := f["first_seen"]; ok {
		t.Error("first_seen should be omitted when zero")
	}
	if _, ok := f["last_seen"]; ok {
		t.Error("last_seen should be omitted when zero")
	}
}

func TestJSONEvidenceOmittedWhenEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewJSONFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	f := out["findings"].([]any)[0].(map[string]any)

	if _, ok := f["evidence"]; ok {
		t.Error("evidence should be omitted when all fields are empty")
	}
}

func TestJSONEvidencePartial(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "p1", Title: "T", Severity: reportx.SeverityLow, Status: reportx.StatusActive,
			Evidence: reportx.Evidence{RawRequest: "GET / HTTP/1.1"},
		}},
	}
	data, _ := format.NewJSONFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	f := out["findings"].([]any)[0].(map[string]any)

	ev, ok := f["evidence"].(map[string]any)
	if !ok {
		t.Fatal("evidence should be present when RawRequest is set")
	}
	if ev["raw_request"] != "GET / HTTP/1.1" {
		t.Errorf("evidence.raw_request = %v", ev["raw_request"])
	}
	if _, ok := ev["raw_response"]; ok {
		t.Error("raw_response should be omitted when empty")
	}
}

func TestJSONEmptyFindings(t *testing.T) {
	data, err := format.NewJSONFormatter().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)

	findings := out["findings"].([]any)
	if len(findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(findings))
	}
	meta := out["metadata"].(map[string]any)
	if meta["total"] != float64(0) {
		t.Errorf("metadata.total = %v, want 0", meta["total"])
	}
}

func TestJSONMediaTypeAndExtension(t *testing.T) {
	f := format.NewJSONFormatter()
	if f.MediaType() != "application/json" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".json" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}
