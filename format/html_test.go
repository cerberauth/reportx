package format_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

func TestHTMLMediaTypeAndExtension(t *testing.T) {
	f := format.NewHTMLFormatter()
	if f.MediaType() != "text/html" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".html" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}

func TestHTMLDoctype(t *testing.T) {
	data, err := format.NewHTMLFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	if !strings.HasPrefix(string(data), "<!DOCTYPE html>") {
		t.Error("should start with <!DOCTYPE html>")
	}
}

func TestHTMLHeadElements(t *testing.T) {
	data, _ := format.NewHTMLFormatter().Format(fullReport())
	s := string(data)
	if !strings.Contains(s, `<meta charset="utf-8">`) {
		t.Error("should contain charset meta tag")
	}
	if !strings.Contains(s, `<meta name="viewport"`) {
		t.Error("should contain viewport meta tag")
	}
	if !strings.Contains(s, "<title>Test Report</title>") {
		t.Error("should contain <title> with report title")
	}
	if !strings.Contains(s, "<style>") {
		t.Error("should contain inline <style>")
	}
}

func TestHTMLDefaultTitle(t *testing.T) {
	data, _ := format.NewHTMLFormatter().Format(emptyReport())
	s := string(data)
	if !strings.Contains(s, "<title>Security Report</title>") {
		t.Error("empty title should default to 'Security Report'")
	}
	if !strings.Contains(s, "<h1>Security Report</h1>") {
		t.Error("empty title should render as 'Security Report' in h1")
	}
}

func TestHTMLHeaderMetadata(t *testing.T) {
	data, _ := format.NewHTMLFormatter().Format(fullReport())
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

func TestHTMLSummaryBadges(t *testing.T) {
	data, _ := format.NewHTMLFormatter().Format(fullReport())
	s := string(data)
	if !strings.Contains(s, `class="summary"`) {
		t.Error("should contain summary section")
	}
	if !strings.Contains(s, `class="badge"`) {
		t.Error("should contain badge elements")
	}
	for _, label := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if !strings.Contains(s, label) {
			t.Errorf("summary should contain %s label", label)
		}
	}
}

func TestHTMLSeveritySectionsOnlyNonEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{
			{ID: "1", Title: "A", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
			{ID: "2", Title: "B", Severity: reportx.SeverityLow, Status: reportx.StatusActive},
		},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "Critical Findings") {
		t.Error("should have Critical Findings section")
	}
	if !strings.Contains(s, "Low Findings") {
		t.Error("should have Low Findings section")
	}
	for _, absent := range []string{"High Findings", "Medium Findings", "Info Findings"} {
		if strings.Contains(s, absent) {
			t.Errorf("should not contain empty section %q", absent)
		}
	}
}

func TestHTMLFindingDetails(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)

	if !strings.Contains(s, "<details>") {
		t.Error("each finding should be in a <details> element")
	}
	if !strings.Contains(s, "Rich Finding") {
		t.Error("should contain finding title")
	}
	if !strings.Contains(s, "https://api.example.com/users") {
		t.Error("should contain finding URL")
	}
	if !strings.Contains(s, "<code>id</code>") {
		t.Error("parameter should be wrapped in <code>")
	}
	if !strings.Contains(s, "CWE-89") {
		t.Error("should contain CWE ID")
	}
	if !strings.Contains(s, "9.3 (CVSS 4.0)") {
		t.Error("should contain CVSS 4.0 score")
	}
	if !strings.Contains(s, "A03:2021") {
		t.Error("should contain OWASP top 10")
	}
	if !strings.Contains(s, "active") {
		t.Error("should contain status")
	}
	if !strings.Contains(s, "abc123") {
		t.Error("should contain fingerprint hash")
	}
	if !strings.Contains(s, "injection, sql") {
		t.Error("should contain tags joined by comma")
	}
}

func TestHTMLFindingFirstLastSeen(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "2024-01-10T08:00:00Z") {
		t.Error("should contain first_seen timestamp")
	}
	if !strings.Contains(s, "2024-01-12T08:00:00Z") {
		t.Error("should contain last_seen timestamp")
	}
}

func TestHTMLFirstLastSeenOmittedWhenZero(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if strings.Contains(s, "First seen") {
		t.Error("First seen should be omitted when zero")
	}
	if strings.Contains(s, "Last seen") {
		t.Error("Last seen should be omitted when zero")
	}
}

func TestHTMLCVSS31FallbackWhenNo40(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			CVSS31Score: 7.5,
		}},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "7.5 (CVSS 3.1)") {
		t.Error("should show CVSS 3.1 score when no 4.0 is set")
	}
}

func TestHTMLDescriptionAndRemediation(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			Description: "Desc text.", Remediation: "Fix it.",
		}},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if !strings.Contains(s, "<h4>Description</h4>") {
		t.Error("should contain Description heading")
	}
	if !strings.Contains(s, "Desc text.") {
		t.Error("should contain description text")
	}
	if !strings.Contains(s, "<h4>Remediation</h4>") {
		t.Error("should contain Remediation heading")
	}
	if !strings.Contains(s, "Fix it.") {
		t.Error("should contain remediation text")
	}
}

func TestHTMLEvidenceInNestedDetails(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "T", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
			Evidence: reportx.Evidence{
				RawRequest:  "GET / HTTP/1.1",
				RawResponse: "HTTP/1.1 200 OK",
			},
		}},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if strings.Count(s, "<details>") < 2 {
		t.Error("evidence should be inside a nested <details> element")
	}
	if !strings.Contains(s, "GET / HTTP/1.1") {
		t.Error("raw request should appear in evidence")
	}
	if !strings.Contains(s, "HTTP/1.1 200 OK") {
		t.Error("raw response should appear in evidence")
	}
	if !strings.Contains(s, "<pre>") {
		t.Error("evidence should be in <pre> blocks")
	}
}

func TestHTMLSpecialCharsEscaped(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "1", Title: "<script>alert(1)</script>", Severity: reportx.SeverityHigh,
			Status:      reportx.StatusActive,
			Description: `<img src="x" onerror="alert(1)">`,
		}},
	}
	data, _ := format.NewHTMLFormatter().Format(r)
	s := string(data)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Error("raw <script> tag in title should be HTML-escaped")
	}
	if strings.Contains(s, `<img src="x"`) {
		t.Error("raw <img> tag in description should be HTML-escaped")
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Error("< should be escaped to &lt;")
	}
}

func TestHTMLPrintCSS(t *testing.T) {
	data, _ := format.NewHTMLFormatter().Format(emptyReport())
	if !strings.Contains(string(data), "@media print") {
		t.Error("should include @media print styles")
	}
}

func TestHTMLEmptyReport(t *testing.T) {
	data, err := format.NewHTMLFormatter().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	s := string(data)
	if !strings.HasPrefix(s, "<!DOCTYPE html>") {
		t.Error("empty report should still produce valid HTML")
	}
	if strings.Contains(s, "<details>") {
		t.Error("empty report should not contain any finding <details>")
	}
}
