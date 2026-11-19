package format_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/internal/testdata"
)

var update = flag.Bool("update", false, "rewrite golden files")

// goldenReport is a fixed report exercising findings of every severity and
// status, rich evidence, scan errors and coverage.
func goldenReport() *reportx.Report {
	t := time.Date(2024, 1, 10, 8, 0, 0, 0, time.UTC)
	rich := reportx.Finding{
		ID:           "rich-1",
		Title:        "Rich Finding",
		Severity:     reportx.SeverityCritical,
		CVSS31Score:  9.8,
		CVSS31Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWEID:        "CWE-89",
		CWEName:      "SQL Injection",
		OwaspTop10:   "A03:2021 – Injection",
		URL:          "https://api.example.com/users?id=1",
		Parameter:    "id",
		Evidence: &evidence.HTTPEvidence{
			RequestMethod:   "GET",
			RequestURL:      "https://api.example.com/users?id=1%27",
			RequestHeaders:  map[string][]string{"Accept": {"application/json"}},
			ResponseStatus:  500,
			ResponseHeaders: map[string][]string{"Content-Type": {"text/plain"}},
			ResponseBody:    []byte("SQL error"),
		},
		Description: "SQL injection via the id parameter.",
		Remediation: "Use parameterized queries.",
		References:  []string{"https://example.com/advisory/42"},
		FirstSeen:   t,
		LastSeen:    t.Add(48 * time.Hour),
		Status:      reportx.StatusActive,
	}
	r := &reportx.Report{
		Title:       "Golden Report",
		ToolName:    "TestScanner",
		ToolVersion: "1.0.0",
		Target:      "https://api.example.com",
		ScanDate:    time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		Findings:    append(testdata.Fixtures(), rich),
		Errors: []reportx.ScanError{
			{CheckID: "check-timeout", Resource: "https://api.example.com/slow", Message: "request timed out"},
		},
		Coverage: reportx.Coverage{Run: 20, Skipped: 1, Errored: 1},
	}
	return r
}

// assertGolden compares got with testdata/golden/<name>, rewriting the file
// when the tests run with -update.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (run with -update to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("output differs from %s (run with -update to accept):\n%s", path, got)
	}
}
