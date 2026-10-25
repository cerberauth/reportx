package format_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

const (
	refEndpoint = "https://api.example.com/users"
	refAdvisory = "https://example.com/advisory/42"
	refSecond   = "https://example.com/docs/sqli"
)

func referencesReport(refs ...string) *reportx.Report {
	return &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{{
			ID:         "f1",
			Title:      "SQL injection",
			Severity:   reportx.SeverityHigh,
			Status:     reportx.StatusActive,
			CWEID:      "CWE-89",
			URL:        refEndpoint,
			References: refs,
		}},
	}
}

func TestReferencesKeepURLAndReferencesInEveryTextFormatter(t *testing.T) {
	formatters := map[string]format.Formatter{
		"json":     format.NewJSONFormatter(),
		"jsonl":    format.NewJSONLFormatter(),
		"yaml":     format.NewYAMLFormatter(),
		"markdown": format.NewMarkdownFormatter(),
		"html":     format.NewHTMLFormatter(),
		"terminal": format.NewTerminalFormatterNoColor(),
	}
	for name, f := range formatters {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(referencesReport(refAdvisory, refSecond))
			if err != nil {
				t.Fatalf("Format() error: %v", err)
			}
			out := string(data)
			for _, want := range []string{refEndpoint, refAdvisory, refSecond} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q", want)
				}
			}
		})
	}
}

func TestReferencesOmittedWhenEmpty(t *testing.T) {
	formatters := map[string]format.Formatter{
		"json":     format.NewJSONFormatter(),
		"jsonl":    format.NewJSONLFormatter(),
		"yaml":     format.NewYAMLFormatter(),
		"markdown": format.NewMarkdownFormatter(),
		"html":     format.NewHTMLFormatter(),
		"terminal": format.NewTerminalFormatterNoColor(),
	}
	for name, f := range formatters {
		t.Run(name, func(t *testing.T) {
			data, err := f.Format(referencesReport())
			if err != nil {
				t.Fatalf("Format() error: %v", err)
			}
			if strings.Contains(strings.ToLower(string(data)), "references") {
				t.Error("output should not mention references when none are set")
			}
		})
	}
}

func TestJSONReferencesField(t *testing.T) {
	data, _ := format.NewJSONFormatter().Format(referencesReport(refAdvisory, refSecond))
	var out struct {
		Findings []struct {
			URL        string   `json:"url"`
			References []string `json:"references"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	got := out.Findings[0]
	if got.URL != refEndpoint {
		t.Errorf("url = %q, want %q", got.URL, refEndpoint)
	}
	if len(got.References) != 2 || got.References[0] != refAdvisory || got.References[1] != refSecond {
		t.Errorf("references = %v", got.References)
	}
}

func TestSARIFReferencesMapToHelpURI(t *testing.T) {
	data, err := format.NewSARIFFormatter().Format(referencesReport(refAdvisory, refSecond))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(data, &out)
	run := sarifFirstRun(t, out)

	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if got := rules[0].(map[string]any)["helpUri"]; got != refAdvisory {
		t.Errorf("helpUri = %v, want %q", got, refAdvisory)
	}

	result := run["results"].([]any)[0].(map[string]any)
	loc := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)
	if loc["uri"] != refEndpoint {
		t.Errorf("artifactLocation.uri = %v, want %q", loc["uri"], refEndpoint)
	}
}

func TestSARIFNoHelpURIWithoutReferences(t *testing.T) {
	data, _ := format.NewSARIFFormatter().Format(referencesReport())
	if strings.Contains(string(data), "helpUri") {
		t.Error("helpUri should be omitted when no references are set")
	}
}

func TestSARIFHelpURIFromLaterFindingOfSameRule(t *testing.T) {
	r := referencesReport()
	r.Findings = append(r.Findings, reportx.Finding{
		ID: "f2", Severity: reportx.SeverityHigh, Status: reportx.StatusActive,
		CWEID: "CWE-89", References: []string{refAdvisory},
	})
	data, _ := format.NewSARIFFormatter().Format(r)
	if !strings.Contains(string(data), `"helpUri": "`+refAdvisory+`"`) {
		t.Error("rule should pick up helpUri from a later finding of the same rule")
	}
}
