package format_test

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

func TestSARIFMediaTypeAndExtension(t *testing.T) {
	f := format.NewSARIFFormatter()
	if f.MediaType() != "application/sarif+json" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".sarif.json" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}

func TestSARIFVersion(t *testing.T) {
	data, err := format.NewSARIFFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)

	if out["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", out["version"])
	}
	schema, _ := out["$schema"].(string)
	if schema == "" {
		t.Error("$schema field should be present")
	}
}

func TestSARIFToolInfo(t *testing.T) {
	r := &reportx.Report{
		ToolName:    "MyScanner",
		ToolVersion: "2.3.4",
		ScanDate:    time.Now(),
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)

	run := sarifFirstRun(t, out)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)

	if driver["name"] != "MyScanner" {
		t.Errorf("driver.name = %v", driver["name"])
	}
	if driver["version"] != "2.3.4" {
		t.Errorf("driver.version = %v", driver["version"])
	}
	if uri, _ := driver["informationUri"].(string); uri == "" {
		t.Error("driver.informationUri should be set")
	}
}

func TestSARIFRulesDeduplicatedByCWE(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "A", Severity: reportx.SeverityCritical, CWEID: "CWE-89", Status: reportx.StatusActive},
			{ID: "2", Title: "B", Severity: reportx.SeverityHigh, CWEID: "CWE-89", Status: reportx.StatusActive},
			{ID: "3", Title: "C", Severity: reportx.SeverityMedium, CWEID: "CWE-79", Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)

	run := sarifFirstRun(t, out)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("rules count = %d, want 2 (one per unique CWE)", len(rules))
	}
}

func TestSARIFRulesSortedAlphabetically(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{CWEID: "CWE-918", Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
			{CWEID: "CWE-22", Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
			{CWEID: "CWE-79", Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)

	run := sarifFirstRun(t, out)
	rawRules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	ids := make([]string, len(rawRules))
	for i, rr := range rawRules {
		ids[i] = rr.(map[string]any)["id"].(string)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("rules are not sorted: %v", ids)
	}
}

func TestSARIFUnknownRuleForMissingCWE(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "No CWE", Severity: reportx.SeverityLow, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)

	run := sarifFirstRun(t, out)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["id"] != "UNKNOWN" {
		t.Errorf("rule.id = %v, want UNKNOWN", rule["id"])
	}

	results := run["results"].([]any)
	res := results[0].(map[string]any)
	if res["ruleId"] != "UNKNOWN" {
		t.Errorf("result.ruleId = %v, want UNKNOWN", res["ruleId"])
	}
}

func TestSARIFSeverityToLevel(t *testing.T) {
	cases := []struct {
		severity reportx.Severity
		want     string
	}{
		{reportx.SeverityCritical, "error"},
		{reportx.SeverityHigh, "error"},
		{reportx.SeverityMedium, "warning"},
		{reportx.SeverityLow, "note"},
		{reportx.SeverityInfo, "note"},
	}
	for _, tc := range cases {
		r := &reportx.Report{
			ToolName: "T",
			ScanDate: time.Now(),
			Findings: []reportx.Finding{
				{ID: "1", Title: "T", Severity: tc.severity, CWEID: "CWE-1", Status: reportx.StatusActive},
			},
		}
		data, _ := format.NewSARIFFormatter().Format(r)
		var out map[string]any
		json.Unmarshal(data, &out)
		run := sarifFirstRun(t, out)
		result := run["results"].([]any)[0].(map[string]any)
		if result["level"] != tc.want {
			t.Errorf("severity %s → level %v, want %s", tc.severity, result["level"], tc.want)
		}
	}
}

func TestSARIFLocationFromURL(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "T", Severity: reportx.SeverityHigh, CWEID: "CWE-79",
				URL: "https://example.com/search", Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)

	locs := result["locations"].([]any)
	if len(locs) != 1 {
		t.Fatalf("locations count = %d, want 1", len(locs))
	}
	loc := locs[0].(map[string]any)
	phys := loc["physicalLocation"].(map[string]any)
	artifact := phys["artifactLocation"].(map[string]any)
	if artifact["uri"] != "https://example.com/search" {
		t.Errorf("artifactLocation.uri = %v", artifact["uri"])
	}
}

func TestSARIFNoLocationWhenURLEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)
	if _, ok := result["locations"]; ok {
		t.Error("locations should be absent when URL is empty")
	}
}

func TestSARIFPartialFingerprintsFromHash(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, CWEID: "CWE-89",
			Status: reportx.StatusActive, FingerprintHash: "deadbeef",
		}},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)

	fp := result["partialFingerprints"].(map[string]any)
	if fp["primaryLocationLineHash"] != "deadbeef" {
		t.Errorf("primaryLocationLineHash = %v", fp["primaryLocationLineHash"])
	}
}

func TestSARIFNoPartialFingerprintsWhenHashEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)
	if _, ok := result["partialFingerprints"]; ok {
		t.Error("partialFingerprints should be absent when FingerprintHash is empty")
	}
}

func TestSARIFSecuritySeverityFromCVSS40(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityCritical, CWEID: "CWE-89",
			CVSS40Score: 9.3, CVSS31Score: 9.8, Status: reportx.StatusActive,
		}},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)

	props := result["properties"].(map[string]any)
	if props["security-severity"] != "9.3" {
		t.Errorf("security-severity = %v, want 9.3", props["security-severity"])
	}
}

func TestSARIFSecuritySeverityFallsBackToCVSS31(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityCritical, CWEID: "CWE-89",
			CVSS31Score: 9.8, Status: reportx.StatusActive,
		}},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)

	props := result["properties"].(map[string]any)
	if props["security-severity"] != "9.8" {
		t.Errorf("security-severity = %v, want 9.8", props["security-severity"])
	}
}

func TestSARIFNoPropertiesWhenNoCVSS(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)
	result := run["results"].([]any)[0].(map[string]any)
	if _, ok := result["properties"]; ok {
		t.Error("properties should be absent when no CVSS score is set")
	}
}

func TestSARIFEmptyFindings(t *testing.T) {
	data, err := format.NewSARIFFormatter().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)

	results := run["results"].([]any)
	if len(results) != 0 {
		t.Errorf("results count = %d, want 0", len(results))
	}
}

func TestSARIFResultCount(t *testing.T) {
	fixtures := fullReport().Findings
	data, err := format.NewSARIFFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)

	results := run["results"].([]any)
	if len(results) != len(fixtures) {
		t.Errorf("results count = %d, want %d", len(results), len(fixtures))
	}
}

func sarifFirstRun(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	runs, ok := out["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("runs array is missing or empty")
	}
	return runs[0].(map[string]any)
}
