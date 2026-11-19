package format

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/cerberauth/reportx"
)

// JUnitFormatter renders a report as JUnit XML: one test suite for the scan
// target, one test case per finding, one per scan error, and, when the report
// carries coverage data, one passing test case per check that ran clean.
//
// JUnit has no severity concept, so FailOn decides which findings fail: a
// finding fails when its severity is at least FailOn. Below the threshold it
// is reported as a passing test case, and findings whose status is not active
// (false positive, accepted risk, mitigated) are reported as skipped.
type JUnitFormatter struct {
	// FailOn is the lowest severity that fails a test case. The report has no
	// fail threshold of its own, so the default (empty) fails on every severity.
	FailOn reportx.Severity
}

func NewJUnitFormatter() *JUnitFormatter { return &JUnitFormatter{} }

// NewJUnitFormatterWithThreshold returns a JUnitFormatter that only fails
// findings at or above the given severity.
func NewJUnitFormatterWithThreshold(failOn reportx.Severity) *JUnitFormatter {
	return &JUnitFormatter{FailOn: failOn}
}

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      string          `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Props     []junitProperty `xml:"properties>property,omitempty"`
	Cases     []junitTestCase `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitResult  `xml:"failure,omitempty"`
	Error     *junitResult  `xml:"error,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitResult struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// severityRank orders severities from most (0) to least severe; unknown values
// sort as most severe so they are never silently ignored by a threshold.
func severityRank(s reportx.Severity) int {
	for i, sev := range severityOrder {
		if sev == s {
			return i
		}
	}
	return -1
}

func (f *JUnitFormatter) fails(s reportx.Severity) bool {
	if f.FailOn == "" {
		return true
	}
	return severityRank(s) <= severityRank(f.FailOn)
}

func junitCaseName(fi reportx.Finding) string {
	name := fi.Title
	if name == "" {
		name = fi.ID
	}
	if fi.URL != "" {
		name += " - " + fi.URL
	}
	if fi.Parameter != "" {
		name += " (" + fi.Parameter + ")"
	}
	return name
}

func junitClassName(fi reportx.Finding) string {
	switch {
	case fi.CWEID != "":
		return fi.CWEID
	case fi.ID != "":
		return fi.ID
	default:
		return "finding"
	}
}

// junitFindingDetails is the human-readable body of a failing test case:
// title, severity and remediation first, then the rest of the context.
func junitFindingDetails(fi reportx.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Title: %s\n", fi.Title)
	fmt.Fprintf(&b, "Severity: %s\n", fi.Severity)
	if fi.CWEID != "" {
		fmt.Fprintf(&b, "CWE: %s\n", fi.CWEID)
	}
	if fi.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", fi.URL)
	}
	if fi.Parameter != "" {
		fmt.Fprintf(&b, "Parameter: %s\n", fi.Parameter)
	}
	if fi.Description != "" {
		fmt.Fprintf(&b, "\nDescription:\n%s\n", fi.Description)
	}
	if fi.Remediation != "" {
		fmt.Fprintf(&b, "\nRemediation:\n%s\n", fi.Remediation)
	}
	if len(fi.References) > 0 {
		b.WriteString("\nReferences:\n")
		for _, ref := range fi.References {
			fmt.Fprintf(&b, "%s\n", ref)
		}
	}
	return b.String()
}

func (f *JUnitFormatter) Format(r *reportx.Report) ([]byte, error) {
	name := r.Target
	if name == "" {
		name = "reportx"
	}

	suite := junitTestSuite{
		Name:      name,
		Time:      "0",
		Timestamp: r.ScanDate.UTC().Format("2006-01-02T15:04:05"),
	}
	if r.ToolName != "" {
		suite.Props = append(suite.Props, junitProperty{Name: "tool", Value: strings.TrimSpace(r.ToolName + " " + r.ToolVersion)})
	}
	if r.Title != "" {
		suite.Props = append(suite.Props, junitProperty{Name: "title", Value: r.Title})
	}

	for _, fi := range r.Findings {
		tc := junitTestCase{Name: junitCaseName(fi), ClassName: junitClassName(fi), Time: "0"}
		details := junitFindingDetails(fi)
		switch {
		case fi.Status != "" && fi.Status != reportx.StatusActive:
			tc.Skipped = &junitSkipped{Message: string(fi.Status)}
			tc.SystemOut = details
			suite.Skipped++
		case f.fails(fi.Severity):
			tc.Failure = &junitResult{Message: fi.Title, Type: string(fi.Severity), Body: details}
			suite.Failures++
		default:
			tc.SystemOut = details
		}
		suite.Cases = append(suite.Cases, tc)
	}

	for _, e := range r.Errors {
		check := e.CheckID
		if check == "" {
			check = "scan"
		}
		caseName := check
		if e.Resource != "" {
			caseName += " - " + e.Resource
		}
		suite.Cases = append(suite.Cases, junitTestCase{
			Name:      caseName,
			ClassName: check,
			Time:      "0",
			Error:     &junitResult{Message: e.Message, Type: "scan_error", Body: e.Message},
		})
		suite.Errors++
	}

	// Coverage tells how many checks ran, so those that produced no finding
	// can be reported as passed. Without it, only findings and errors appear.
	if !r.Coverage.IsZero() {
		for i := 1; i <= r.Coverage.Run-len(r.Findings); i++ {
			suite.Cases = append(suite.Cases, junitTestCase{
				Name:      fmt.Sprintf("check %d passed", i),
				ClassName: "coverage",
				Time:      "0",
			})
		}
	}

	suite.Tests = len(suite.Cases)
	root := junitTestSuites{
		Name:     name,
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Errors:   suite.Errors,
		Skipped:  suite.Skipped,
		Suites:   []junitTestSuite{suite},
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}

func (f *JUnitFormatter) MediaType() string     { return "application/xml" }
func (f *JUnitFormatter) FileExtension() string { return ".junit.xml" }
