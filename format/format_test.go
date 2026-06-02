package format_test

import (
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/internal/testdata"
)

func fullReport() *reportx.Report {
	return &reportx.Report{
		Title:       "Test Report",
		ToolName:    "TestScanner",
		ToolVersion: "1.0.0",
		Target:      "https://api.example.com",
		ScanDate:    time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		Findings:    testdata.Fixtures(),
	}
}

func minimalFinding() reportx.Finding {
	return reportx.Finding{
		ID:       "min-1",
		Title:    "Minimal Finding",
		Severity: reportx.SeverityLow,
		Status:   reportx.StatusActive,
	}
}

func emptyReport() *reportx.Report {
	return &reportx.Report{
		ToolName: "EmptyScanner",
		ScanDate: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		Target:   "https://empty.example.com",
	}
}

func richFinding() reportx.Finding {
	t := time.Date(2024, 1, 10, 8, 0, 0, 0, time.UTC)
	return reportx.Finding{
		ID:              "rich-1",
		Title:           "Rich Finding",
		Severity:        reportx.SeverityCritical,
		CVSS31Score:     9.8,
		CVSS31Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSS40Score:     9.3,
		CVSS40Vector:    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		CWEID:           "CWE-89",
		CWEName:         "Improper Neutralization of Special Elements used in an SQL Command",
		OwaspTop10:      "A03:2021 – Injection",
		URL:             "https://api.example.com/users",
		Parameter:       "id",
		Evidence:        reportx.Evidence{RawRequest: "GET /users?id=1' HTTP/1.1", RawResponse: "HTTP/1.1 500 Internal Server Error"},
		Description:     "SQL injection via the id parameter.",
		Remediation:     "Use parameterized queries.",
		FirstSeen:       t,
		LastSeen:        t.Add(48 * time.Hour),
		Status:          reportx.StatusActive,
		FingerprintHash: "abc123",
		Tags:            []string{"injection", "sql"},
		Extra:           map[string]string{"scanner": "zap"},
	}
}

func init() {
	var _ format.Formatter = format.NewJSONFormatter()
	var _ format.Formatter = format.NewJSONLFormatter()
	var _ format.Formatter = format.NewSARIFFormatter()
	var _ format.Formatter = format.NewMarkdownFormatter()
	var _ format.Formatter = format.NewHTMLFormatter()
	var _ format.Formatter = format.NewTerminalFormatter()
	var _ format.Formatter = format.NewTerminalFormatterNoColor()
}
