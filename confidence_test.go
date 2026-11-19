package reportx_test

import (
	"context"
	"testing"

	"github.com/cerberauth/reportx"
)

func TestConfidenceAtLeast(t *testing.T) {
	tests := []struct {
		c, min reportx.Confidence
		want   bool
	}{
		{reportx.ConfidenceConfirmed, reportx.ConfidenceConfirmed, true},
		{reportx.ConfidenceConfirmed, reportx.ConfidenceTentative, true},
		{reportx.ConfidenceFirm, reportx.ConfidenceConfirmed, false},
		{reportx.ConfidenceFirm, reportx.ConfidenceFirm, true},
		{reportx.ConfidenceTentative, reportx.ConfidenceFirm, false},
		{"", reportx.ConfidenceConfirmed, true},
		{reportx.ConfidenceTentative, "", true},
	}
	for _, tc := range tests {
		if got := tc.c.AtLeast(tc.min); got != tc.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", tc.c, tc.min, got, tc.want)
		}
	}
}

func confidenceFindings() []reportx.Finding {
	return []reportx.Finding{
		{ID: "c", Severity: reportx.SeverityHigh, Confidence: reportx.ConfidenceConfirmed},
		{ID: "f", Severity: reportx.SeverityHigh, Confidence: reportx.ConfidenceFirm},
		{ID: "t", Severity: reportx.SeverityHigh, Confidence: reportx.ConfidenceTentative},
		{ID: "u", Severity: reportx.SeverityHigh},
	}
}

func ids(findings []reportx.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReportConfidenceHelpers(t *testing.T) {
	r := &reportx.Report{Findings: confidenceFindings()}

	if got := ids(r.FindingsByConfidence(reportx.ConfidenceFirm)); !equal(got, []string{"f"}) {
		t.Errorf("FindingsByConfidence(firm) = %v", got)
	}
	if got := ids(r.FindingsByConfidence("")); !equal(got, []string{"u"}) {
		t.Errorf("FindingsByConfidence(\"\") = %v", got)
	}
	if got := ids(r.FindingsAtLeast(reportx.ConfidenceFirm)); !equal(got, []string{"c", "f", "u"}) {
		t.Errorf("FindingsAtLeast(firm) = %v", got)
	}
	if got := ids(r.FindingsAtLeast("")); len(got) != 4 {
		t.Errorf("FindingsAtLeast(\"\") = %v, want all findings", got)
	}
}

func TestBuilderMinConfidence(t *testing.T) {
	r, err := reportx.NewBuilder().
		Findings(confidenceFindings()).
		MinConfidence(reportx.ConfidenceConfirmed).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(r.Findings); !equal(got, []string{"c", "u"}) {
		t.Errorf("findings = %v, want [c u]", got)
	}
}

func TestBuilderWithoutMinConfidenceKeepsAll(t *testing.T) {
	r, err := reportx.NewBuilder().Findings(confidenceFindings()).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 4 {
		t.Errorf("got %d findings, want 4", len(r.Findings))
	}
}
