package format_test

import (
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"gopkg.in/yaml.v3"
)

func TestYAMLMetadata(t *testing.T) {
	r := fullReport()
	data, err := format.NewYAMLFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}

	meta := out["metadata"].(map[string]any)
	if meta["title"] != "Test Report" {
		t.Errorf("metadata.title = %v", meta["title"])
	}
	if meta["tool"] != "TestScanner" {
		t.Errorf("metadata.tool = %v", meta["tool"])
	}
	if meta["target"] != "https://api.example.com" {
		t.Errorf("metadata.target = %v", meta["target"])
	}
}

func TestYAMLFindingFields(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, err := format.NewYAMLFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	findings := out["findings"].([]any)
	f := findings[0].(map[string]any)

	checks := map[string]any{
		"id":          "rich-1",
		"title":       "Rich Finding",
		"severity":    "critical",
		"cwe_id":      "CWE-89",
		"owasp_top10": "A03:2021 – Injection",
		"url":         "https://api.example.com/users",
		"parameter":   "id",
		"status":      "active",
	}
	for key, want := range checks {
		if f[key] != want {
			t.Errorf("finding.%s = %v, want %v", key, f[key], want)
		}
	}

	ev := f["evidence"].(map[string]any)
	if ev["raw_request"] != "GET /users?id=1' HTTP/1.1" {
		t.Errorf("finding.evidence.raw_request = %v", ev["raw_request"])
	}
}

func TestYAMLCAPECAndRequestHeaders(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "c1", Title: "T", Severity: reportx.SeverityLow, Status: reportx.StatusActive,
			CAPECID: "CAPEC-31",
		}},
	}
	data, err := format.NewYAMLFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	f := out["findings"].([]any)[0].(map[string]any)
	if f["capec_id"] != "CAPEC-31" {
		t.Errorf("finding.capec_id = %v, want CAPEC-31", f["capec_id"])
	}
}

func TestYAMLMediaTypeAndExtension(t *testing.T) {
	f := format.NewYAMLFormatter()
	if f.MediaType() != "application/yaml" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".yaml" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}
