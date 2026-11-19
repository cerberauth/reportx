package format_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
)

type junitDoc struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Errors   int `xml:"errors,attr"`
	Skipped  int `xml:"skipped,attr"`
	Suites   []struct {
		Name  string `xml:"name,attr"`
		Tests int    `xml:"tests,attr"`
		Cases []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Type    string `xml:"type,attr"`
				Body    string `xml:",chardata"`
			} `xml:"failure"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error"`
			Skipped *struct{} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func parseJUnit(t *testing.T, data []byte) junitDoc {
	t.Helper()
	var doc junitDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid XML: %v\n%s", err, data)
	}
	return doc
}

func TestJUnitGolden(t *testing.T) {
	data, err := format.NewJUnitFormatter().Format(goldenReport())
	if err != nil {
		t.Fatal(err)
	}
	parseJUnit(t, data)
	assertGolden(t, "report.junit.xml", data)
}

func TestJUnitThresholdGolden(t *testing.T) {
	data, err := format.NewJUnitFormatterWithThreshold(reportx.SeverityHigh).Format(goldenReport())
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "report.junit-high.xml", data)
}

func TestJUnitStructure(t *testing.T) {
	data, _ := format.NewJUnitFormatter().Format(goldenReport())
	doc := parseJUnit(t, data)
	if len(doc.Suites) != 1 || doc.Suites[0].Name != "https://api.example.com" {
		t.Fatalf("want one suite named after the target, got %+v", doc.Suites)
	}
	suite := doc.Suites[0]

	// 9 findings (8 fixtures + 1 rich) + 1 scan error + (20 run − 9 findings) passed checks.
	if want := 9 + 1 + 11; len(suite.Cases) != want || doc.Tests != want {
		t.Errorf("cases = %d, tests attr = %d, want %d", len(suite.Cases), doc.Tests, want)
	}
	// Active findings fail; mitigated, accepted-risk and false-positive ones are skipped.
	if doc.Failures != 6 || doc.Skipped != 3 || doc.Errors != 1 {
		t.Errorf("failures/skipped/errors = %d/%d/%d, want 6/3/1", doc.Failures, doc.Skipped, doc.Errors)
	}
	first := suite.Cases[0]
	if first.Failure == nil || first.Failure.Type != "critical" || first.Failure.Message != "SQL Injection in login endpoint" {
		t.Fatalf("first failure = %+v", first.Failure)
	}
	for _, want := range []string{"Severity: critical", "Remediation:", "Use parameterized queries"} {
		if !strings.Contains(first.Failure.Body, want) {
			t.Errorf("failure body missing %q:\n%s", want, first.Failure.Body)
		}
	}
}

func TestJUnitThresholdDecidesFailures(t *testing.T) {
	r := &reportx.Report{Target: "t", Findings: []reportx.Finding{
		{ID: "a", Title: "A", Severity: reportx.SeverityCritical, Status: reportx.StatusActive},
		{ID: "b", Title: "B", Severity: reportx.SeverityMedium, Status: reportx.StatusActive},
		{ID: "c", Title: "C", Severity: reportx.SeverityInfo, Status: reportx.StatusActive},
	}}
	for failOn, want := range map[reportx.Severity]int{
		"":                       3,
		reportx.SeverityInfo:     3,
		reportx.SeverityMedium:   2,
		reportx.SeverityCritical: 1,
	} {
		data, _ := format.NewJUnitFormatterWithThreshold(failOn).Format(r)
		if got := parseJUnit(t, data).Failures; got != want {
			t.Errorf("FailOn %q: failures = %d, want %d", failOn, got, want)
		}
	}
}

func TestJUnitWithoutCoverageHasNoPassedChecks(t *testing.T) {
	data, _ := format.NewJUnitFormatter().Format(fullReport())
	doc := parseJUnit(t, data)
	if len(doc.Suites[0].Cases) != len(fullReport().Findings) {
		t.Errorf("cases = %d, want one per finding", len(doc.Suites[0].Cases))
	}
}

func TestJUnitEscapesText(t *testing.T) {
	r := &reportx.Report{Target: "t", Findings: []reportx.Finding{{
		ID: "x", Title: `<script>&"`, Severity: reportx.SeverityLow, Status: reportx.StatusActive,
		Description: "a < b & c",
	}}}
	data, _ := format.NewJUnitFormatter().Format(r)
	doc := parseJUnit(t, data)
	if doc.Suites[0].Cases[0].Failure.Message != `<script>&"` {
		t.Errorf("message round-trip failed: %q", doc.Suites[0].Cases[0].Failure.Message)
	}
}
