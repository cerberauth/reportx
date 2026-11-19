package format_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

func confidenceReport(c reportx.Confidence) *reportx.Report {
	return &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID:         "f1",
			Title:      "Probable SQL injection",
			Severity:   reportx.SeverityHigh,
			Status:     reportx.StatusActive,
			CWEID:      "CWE-89",
			Confidence: c,
		}},
	}
}

func textFormatters() map[string]format.Formatter {
	return map[string]format.Formatter{
		"json":     format.NewJSONFormatter(),
		"jsonl":    format.NewJSONLFormatter(),
		"yaml":     format.NewYAMLFormatter(),
		"markdown": format.NewMarkdownFormatter(),
		"html":     format.NewHTMLFormatter(),
		"terminal": format.NewTerminalFormatterNoColor(),
	}
}

func TestConfidenceShownInEveryTextFormatter(t *testing.T) {
	for name, f := range textFormatters() {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(confidenceReport(reportx.ConfidenceTentative))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "tentative") {
				t.Errorf("output missing confidence:\n%s", data)
			}
		})
	}
}

func TestConfidenceOmittedWhenUnspecified(t *testing.T) {
	for name, f := range textFormatters() {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(confidenceReport(""))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(data)), "confidence") {
				t.Errorf("output should not mention confidence when unset:\n%s", data)
			}
		})
	}
	data, _ := format.NewSARIFFormatter().Format(confidenceReport(""))
	if s := string(data); strings.Contains(s, "confidence") || strings.Contains(s, `"rank"`) {
		t.Errorf("SARIF should not carry rank/confidence when unset:\n%s", s)
	}
}

func TestJSONConfidenceField(t *testing.T) {
	data, _ := format.NewJSONFormatter().Format(confidenceReport(reportx.ConfidenceFirm))
	var out struct {
		Findings []struct {
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.Findings[0].Confidence; got != "firm" {
		t.Errorf("confidence = %q, want firm", got)
	}
}

func TestSARIFConfidenceRankAndProperties(t *testing.T) {
	want := map[reportx.Confidence]float64{
		reportx.ConfidenceConfirmed: 100,
		reportx.ConfidenceFirm:      70,
		reportx.ConfidenceTentative: 30,
	}
	for c, rank := range want {
		data, err := format.NewSARIFFormatter().Format(confidenceReport(c))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		result := sarifFirstRun(t, out)["results"].([]any)[0].(map[string]any)
		if got := result["rank"]; got != rank {
			t.Errorf("%s: rank = %v, want %v", c, got, rank)
		}
		if got := result["properties"].(map[string]any)["confidence"]; got != string(c) {
			t.Errorf("%s: properties.confidence = %v", c, got)
		}
	}
}

func TestSchemaURLsUseBumpedVersion(t *testing.T) {
	for _, u := range []string{format.ReportSchemaURL, format.FindingSchemaURL} {
		if !strings.Contains(u, "/v0.5.0/") {
			t.Errorf("schema URL %q not bumped to v0.5.0", u)
		}
	}
}
