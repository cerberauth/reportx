package format_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

func scanStatusReport(withStatus bool) *reportx.Report {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID: "f1", Title: "Issue", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
		}},
	}
	if withStatus {
		r.Errors = []reportx.ScanError{
			{CheckID: "jwt-none", Resource: "https://api.example.com/a", Message: "timeout after 5s"},
			{CheckID: "jwt-weak", Message: "connection refused"},
		}
		r.Coverage = reportx.Coverage{Run: 10, Skipped: 3, Errored: 2}
	}
	return r
}

func TestScanStatusTextFormatters(t *testing.T) {
	formatters := map[string]format.Formatter{
		"json":     format.NewJSONFormatter(),
		"jsonl":    format.NewJSONLFormatter(),
		"yaml":     format.NewYAMLFormatter(),
		"sarif":    format.NewSARIFFormatter(),
		"markdown": format.NewMarkdownFormatter(),
		"html":     format.NewHTMLFormatter(),
		"terminal": format.NewTerminalFormatterNoColor(),
	}
	for name, f := range formatters {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(scanStatusReport(true))
			if err != nil {
				t.Fatalf("Format() error: %v", err)
			}
			out := string(data)
			for _, want := range []string{"jwt-none", "jwt-weak", "timeout after 5s", "connection refused", "https://api.example.com/a"} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q", want)
				}
			}
		})
	}
}

func TestScanStatusSectionHeadings(t *testing.T) {
	cases := map[string]struct {
		f    format.Formatter
		want string
	}{
		"markdown": {format.NewMarkdownFormatter(), "## Errors / Coverage"},
		"html":     {format.NewHTMLFormatter(), "Errors / Coverage"},
		"terminal": {format.NewTerminalFormatterNoColor(), "ERRORS / COVERAGE"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			data, _ := c.f.Format(scanStatusReport(true))
			if !strings.Contains(string(data), c.want) {
				t.Errorf("output missing heading %q", c.want)
			}
		})
	}
}

func TestScanStatusCoverageNumbers(t *testing.T) {
	md, _ := format.NewMarkdownFormatter().Format(scanStatusReport(true))
	if !strings.Contains(string(md), "| 10 | 3 | 2 |") {
		t.Errorf("markdown coverage row missing:\n%s", md)
	}
	term, _ := format.NewTerminalFormatterNoColor().Format(scanStatusReport(true))
	if !strings.Contains(string(term), "10 run, 3 skipped, 2 errored") {
		t.Errorf("terminal coverage line missing:\n%s", term)
	}
	h, _ := format.NewHTMLFormatter().Format(scanStatusReport(true))
	if !strings.Contains(string(h), "<dt>Run</dt><dd>10</dd><dt>Skipped</dt><dd>3</dd><dt>Errored</dt><dd>2</dd>") {
		t.Error("html coverage list missing")
	}
}

func TestScanStatusMarkdownEscapesCells(t *testing.T) {
	r := scanStatusReport(false)
	r.Errors = []reportx.ScanError{{CheckID: "c", Message: "a|b\nc"}}
	data, _ := format.NewMarkdownFormatter().Format(r)
	if !strings.Contains(string(data), `| c |  | a\|b c |`) {
		t.Errorf("cell not escaped:\n%s", data)
	}
}

func TestScanStatusHTMLEscapes(t *testing.T) {
	r := scanStatusReport(false)
	r.Errors = []reportx.ScanError{{CheckID: "c", Message: "<script>x</script>"}}
	data, _ := format.NewHTMLFormatter().Format(r)
	if strings.Contains(string(data), "<script>x") {
		t.Error("html must escape error messages")
	}
}

func TestScanStatusJSONShape(t *testing.T) {
	data, _ := format.NewJSONFormatter().Format(scanStatusReport(true))
	var out struct {
		Errors []struct {
			CheckID  string `json:"check_id"`
			Resource string `json:"resource"`
			Message  string `json:"message"`
		} `json:"errors"`
		Coverage struct{ Run, Skipped, Errored int } `json:"coverage"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) != 2 || out.Errors[0].CheckID != "jwt-none" || out.Errors[0].Resource != "https://api.example.com/a" {
		t.Errorf("errors = %+v", out.Errors)
	}
	if out.Coverage.Run != 10 || out.Coverage.Skipped != 3 || out.Coverage.Errored != 2 {
		t.Errorf("coverage = %+v", out.Coverage)
	}
}

func TestScanStatusJSONLTrailingLine(t *testing.T) {
	data, _ := format.NewJSONLFormatter().Format(scanStatusReport(true))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (finding + scan_summary)", len(lines))
	}
	var sum map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &sum); err != nil {
		t.Fatal(err)
	}
	if sum["type"] != "scan_summary" || sum["errors"] == nil || sum["coverage"] == nil {
		t.Errorf("summary line = %v", sum)
	}
}

func TestScanStatusSARIFInvocation(t *testing.T) {
	data, _ := format.NewSARIFFormatter().Format(scanStatusReport(true))
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)

	inv := run["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false {
		t.Errorf("executionSuccessful = %v, want false", inv["executionSuccessful"])
	}
	notes := inv["toolExecutionNotifications"].([]any)
	if len(notes) != 2 {
		t.Fatalf("notifications = %d, want 2", len(notes))
	}
	n := notes[0].(map[string]any)
	if n["level"] != "error" || n["message"].(map[string]any)["text"] != "timeout after 5s" ||
		n["associatedRule"].(map[string]any)["id"] != "jwt-none" {
		t.Errorf("notification = %v", n)
	}
	cov := run["properties"].(map[string]any)["coverage"].(map[string]any)
	if cov["run"] != float64(10) || cov["skipped"] != float64(3) || cov["errored"] != float64(2) {
		t.Errorf("coverage = %v", cov)
	}
}

func TestScanStatusBackCompat(t *testing.T) {
	forbidden := map[string][]string{
		"json":     {`"errors"`, `"coverage"`},
		"yaml":     {"errors:", "coverage:"},
		"jsonl":    {"scan_summary"},
		"sarif":    {"invocations", "toolExecutionNotifications", "coverage"},
		"markdown": {"Errors / Coverage"},
		"html":     {"Errors / Coverage"},
		"terminal": {"ERRORS / COVERAGE"},
	}
	formatters := map[string]format.Formatter{
		"json":     format.NewJSONFormatter(),
		"jsonl":    format.NewJSONLFormatter(),
		"yaml":     format.NewYAMLFormatter(),
		"sarif":    format.NewSARIFFormatter(),
		"markdown": format.NewMarkdownFormatter(),
		"html":     format.NewHTMLFormatter(),
		"terminal": format.NewTerminalFormatterNoColor(),
	}
	for name, f := range formatters {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(scanStatusReport(false))
			if err != nil {
				t.Fatalf("Format() error: %v", err)
			}
			for _, s := range forbidden[name] {
				if strings.Contains(string(data), s) {
					t.Errorf("output must not contain %q without errors/coverage", s)
				}
			}
		})
	}
}

func TestScanStatusSARIFSuccessfulWhenCoverageOnly(t *testing.T) {
	r := scanStatusReport(false)
	r.Coverage = reportx.Coverage{Run: 5}
	data, _ := format.NewSARIFFormatter().Format(r)
	var out map[string]any
	json.Unmarshal(data, &out)
	inv := sarifFirstRun(t, out)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != true {
		t.Errorf("executionSuccessful = %v, want true", inv["executionSuccessful"])
	}
}
