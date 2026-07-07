package format_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

func TestTerminalMediaTypeAndExtension(t *testing.T) {
	f := format.NewTerminalFormatter()
	if f.MediaType() != "text/plain" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".txt" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}

func TestTerminalTitle(t *testing.T) {
	data, err := format.NewTerminalFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	if !strings.Contains(string(data), "Test Report") {
		t.Error("should contain report title")
	}
}

func TestTerminalDefaultTitle(t *testing.T) {
	data, _ := format.NewTerminalFormatterNoColor().Format(emptyReport())
	if !strings.Contains(string(data), "Security Report") {
		t.Error("empty title should default to 'Security Report'")
	}
}

func TestTerminalHeaderFields(t *testing.T) {
	data, _ := format.NewTerminalFormatterNoColor().Format(fullReport())
	s := string(data)
	if !strings.Contains(s, "https://api.example.com") {
		t.Error("should contain target URL")
	}
	if !strings.Contains(s, "TestScanner") {
		t.Error("should contain tool name")
	}
	if !strings.Contains(s, "1.0.0") {
		t.Error("should contain tool version")
	}
	if !strings.Contains(s, "2024-01-15T12:00:00Z") {
		t.Error("should contain scan date in RFC3339")
	}
}

func TestTerminalSummarySection(t *testing.T) {
	data, _ := format.NewTerminalFormatterNoColor().Format(fullReport())
	s := string(data)
	if !strings.Contains(s, "SUMMARY") {
		t.Error("should contain SUMMARY section")
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if !strings.Contains(s, sev) {
			t.Errorf("summary should list %s severity", sev)
		}
	}
	if !strings.Contains(s, "Total") {
		t.Error("summary should contain Total count")
	}
}

func TestTerminalSeverityFindingSections(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "A", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
			{ID: "2", Title: "B", Severity: reportx.SeverityLow, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewTerminalFormatterNoColor().Format(r)
	s := string(data)
	if !strings.Contains(s, "CRITICAL FINDINGS") {
		t.Error("should contain CRITICAL FINDINGS section heading")
	}
	if !strings.Contains(s, "LOW FINDINGS") {
		t.Error("should contain LOW FINDINGS section heading")
	}
	for _, absent := range []string{"HIGH FINDINGS", "MEDIUM FINDINGS", "INFO FINDINGS"} {
		if strings.Contains(s, absent) {
			t.Errorf("should not contain %s when no findings exist for that severity", absent)
		}
	}
}

func TestTerminalFindingFields(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewTerminalFormatterNoColor().Format(r)
	s := string(data)

	if !strings.Contains(s, "Rich Finding") {
		t.Error("should contain finding title")
	}
	if !strings.Contains(s, "https://api.example.com/users") {
		t.Error("should contain finding URL")
	}
	if !strings.Contains(s, "id") {
		t.Error("should contain parameter name")
	}
	if !strings.Contains(s, "CWE-89") {
		t.Error("should contain CWE ID")
	}
	if !strings.Contains(s, "Improper Neutralization") {
		t.Error("should contain CWE name")
	}
	if !strings.Contains(s, "9.3") {
		t.Error("should contain CVSS 4.0 score")
	}
	if !strings.Contains(s, "A03:2021") {
		t.Error("should contain OWASP top 10")
	}
	if !strings.Contains(s, "active") {
		t.Error("should contain status")
	}
	if !strings.Contains(s, "injection") {
		t.Error("should contain tags")
	}
}

func TestTerminalDescriptionAndRemediation(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			Description: "Desc text.", Remediation: "Fix it.",
		}},
	}
	data, _ := format.NewTerminalFormatterNoColor().Format(r)
	s := string(data)
	if !strings.Contains(s, "Description") {
		t.Error("should contain Description label")
	}
	if !strings.Contains(s, "Desc text.") {
		t.Error("should contain description text")
	}
	if !strings.Contains(s, "Remediation") {
		t.Error("should contain Remediation label")
	}
	if !strings.Contains(s, "Fix it.") {
		t.Error("should contain remediation text")
	}
}

func TestTerminalNoDescriptionOrRemediationWhenEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewTerminalFormatterNoColor().Format(r)
	s := string(data)
	if strings.Contains(s, "Description\n      \n") {
		t.Error("should not output empty Description block")
	}
}

func TestTerminalNoColorStripsANSI(t *testing.T) {
	data, err := format.NewTerminalFormatterNoColor().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	if strings.Contains(string(data), "\033[") {
		t.Error("NoColor variant should not contain ANSI escape codes")
	}
}

func TestTerminalColoredContainsANSI(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "A", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewTerminalFormatter().Format(r)
	if !strings.Contains(string(data), "\033[") {
		t.Error("colored variant should contain ANSI escape codes")
	}
}

func TestTerminalEmptyReport(t *testing.T) {
	data, err := format.NewTerminalFormatterNoColor().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "SUMMARY") {
		t.Error("empty report should still show SUMMARY")
	}
	for _, sev := range []string{"CRITICAL FINDINGS", "HIGH FINDINGS", "MEDIUM FINDINGS", "LOW FINDINGS", "INFO FINDINGS"} {
		if strings.Contains(s, sev) {
			t.Errorf("empty report should not contain finding section %q", sev)
		}
	}
}

func TestTerminalMultipleFindingsSeparated(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "First", Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
			{ID: "2", Title: "Second", Severity: reportx.SeverityHigh, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewTerminalFormatterNoColor().Format(r)
	s := string(data)
	if !strings.Contains(s, "First") || !strings.Contains(s, "Second") {
		t.Error("both finding titles should appear in output")
	}
}

func TestTerminalReferrerTagAppendedToURL(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewTerminalFormatterWithReferrerTag("myreport").Format(r)
	if !strings.Contains(string(data), "https://api.example.com/users?ref=myreport") {
		t.Error("URL should be tagged with ref query param")
	}
}

func TestTerminalNoReferrerTagByDefault(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewTerminalFormatter().Format(r)
	if strings.Contains(string(data), "ref=") {
		t.Error("URL should not be tagged when ReferrerTag unset")
	}
}
