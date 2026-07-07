package format_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/format"
)

func TestMarkdownMediaTypeAndExtension(t *testing.T) {
	f := format.NewMarkdownFormatter()
	if f.MediaType() != "text/markdown" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".md" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}

func TestMarkdownTitle(t *testing.T) {
	data, err := format.NewMarkdownFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	s := string(data)
	if !strings.HasPrefix(s, "# Test Report\n") {
		t.Errorf("should start with '# Test Report', got: %q", s[:min(40, len(s))])
	}
}

func TestMarkdownDefaultTitle(t *testing.T) {
	r := emptyReport()
	data, _ := format.NewMarkdownFormatter().Format(r)
	if !strings.HasPrefix(string(data), "# Security Report\n") {
		t.Error("empty title should default to 'Security Report'")
	}
}

func TestMarkdownMetadataLine(t *testing.T) {
	data, _ := format.NewMarkdownFormatter().Format(fullReport())
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

func TestMarkdownSummaryTable(t *testing.T) {
	data, _ := format.NewMarkdownFormatter().Format(fullReport())
	s := string(data)
	if !strings.Contains(s, "## Summary") {
		t.Error("should contain ## Summary section")
	}
	if !strings.Contains(s, "| Severity | Count |") {
		t.Error("should contain severity table header")
	}
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if !strings.Contains(s, "| "+sev+" |") {
			t.Errorf("summary table should contain row for %s", sev)
		}
	}
}

func TestMarkdownSeveritySectionsOnlyNonEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "A", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
			{ID: "2", Title: "B", Severity: reportx.SeverityLow, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)

	if !strings.Contains(s, "## Critical findings") {
		t.Error("should have ## Critical findings section")
	}
	if !strings.Contains(s, "## Low findings") {
		t.Error("should have ## Low findings section")
	}
	for _, absent := range []string{"## High findings", "## Medium findings", "## Info findings"} {
		if strings.Contains(s, absent) {
			t.Errorf("should not contain empty section %q", absent)
		}
	}
}

func TestMarkdownFindingHeading(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "SQL Injection", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	if !strings.Contains(string(data), "### SQL Injection") {
		t.Error("finding should appear as ### heading")
	}
}

func TestMarkdownFindingTableFields(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)

	if !strings.Contains(s, "https://api.example.com/users") {
		t.Error("should contain finding URL")
	}
	if !strings.Contains(s, "`id`") {
		t.Error("should contain parameter in backticks")
	}
	if !strings.Contains(s, "CWE-89") {
		t.Error("should contain CWE ID")
	}
	if !strings.Contains(s, "Improper Neutralization") {
		t.Error("should contain CWE name when present")
	}
	if !strings.Contains(s, "A03:2021") {
		t.Error("should contain OWASP top 10")
	}
	if !strings.Contains(s, "active") {
		t.Error("should contain status")
	}
}

func TestMarkdownCVSS40TakesPrecedence(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityCritical, Status: reportx.StatusActive,
			CVSS40Score: 9.3, CVSS31Score: 9.8,
		}},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "CVSS 4.0") {
		t.Error("CVSS 4.0 should take precedence when both scores are set")
	}
	if strings.Contains(s, "CVSS 3.1") {
		t.Error("CVSS 3.1 should not appear when CVSS 4.0 is set")
	}
}

func TestMarkdownCVSS31FallbackWhenNo40(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			CVSS31Score: 7.5,
		}},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	if !strings.Contains(string(data), "CVSS 3.1") {
		t.Error("CVSS 3.1 should appear when no 4.0 score is set")
	}
}

func TestMarkdownCWENameCombined(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			CWEID: "CWE-79", CWEName: "Cross-site Scripting",
		}},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "CWE-79 – Cross-site Scripting") {
		t.Error("CWE cell should combine ID and name with em dash")
	}
}

func TestMarkdownDescriptionAndRemediation(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			Description: "Desc text here.", Remediation: "Fix it now.",
		}},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "**Description**") {
		t.Error("should contain **Description** heading")
	}
	if !strings.Contains(s, "Desc text here.") {
		t.Error("should contain description text")
	}
	if !strings.Contains(s, "**Remediation**") {
		t.Error("should contain **Remediation** heading")
	}
	if !strings.Contains(s, "Fix it now.") {
		t.Error("should contain remediation text")
	}
}

func TestMarkdownNoDescriptionOrRemediationWhenEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)
	if strings.Contains(s, "**Description**") {
		t.Error("should not output **Description** when empty")
	}
	if strings.Contains(s, "**Remediation**") {
		t.Error("should not output **Remediation** when empty")
	}
}

func TestMarkdownEvidenceInDetails(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			Evidence: &evidence.HTTPEvidence{
				RawRequest:  "GET / HTTP/1.1",
				RawResponse: "HTTP/1.1 200 OK",
			},
		}},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "<details>") {
		t.Error("evidence should be wrapped in <details>")
	}
	if !strings.Contains(s, "GET / HTTP/1.1") {
		t.Error("raw request should appear in evidence")
	}
	if !strings.Contains(s, "HTTP/1.1 200 OK") {
		t.Error("raw response should appear in evidence")
	}
	if !strings.Contains(s, "```http") {
		t.Error("evidence should be in ```http code blocks")
	}
}

func TestMarkdownNoEvidenceBlockWhenEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	if strings.Contains(string(data), "<details>") {
		t.Error("should not output <details> block when evidence is empty")
	}
}

func TestMarkdownEmptyReport(t *testing.T) {
	data, err := format.NewMarkdownFormatter().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "## Summary") {
		t.Error("summary should always be present")
	}
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if strings.Contains(s, "## "+sev+" findings") {
			t.Errorf("should not contain finding section for %s when count is 0", sev)
		}
	}
}

func TestMarkdownReferrerTagAppendedToURL(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewMarkdownFormatterWithReferrerTag("myreport").Format(r)
	if !strings.Contains(string(data), "https://api.example.com/users?ref=myreport") {
		t.Error("URL should be tagged with ref query param")
	}
}

func TestMarkdownNoReferrerTagByDefault(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewMarkdownFormatter().Format(r)
	if strings.Contains(string(data), "ref=") {
		t.Error("URL should not be tagged when ReferrerTag unset")
	}
}
