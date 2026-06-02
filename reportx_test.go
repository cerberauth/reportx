package reportx_test

import (
	"context"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/dedup"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/internal/testdata"
)

func TestBuilderBasic(t *testing.T) {
	fixtures := testdata.Fixtures()
	report, err := reportx.NewBuilder().
		Tool("TestScanner", "1.0.0").
		Target("https://api.example.com").
		Title("Test scan").
		Findings(fixtures).
		Build(context.Background())
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if report.ToolName != "TestScanner" {
		t.Errorf("ToolName = %q, want %q", report.ToolName, "TestScanner")
	}
	if report.ToolVersion != "1.0.0" {
		t.Errorf("ToolVersion = %q, want %q", report.ToolVersion, "1.0.0")
	}
	if report.Target != "https://api.example.com" {
		t.Errorf("Target = %q, want %q", report.Target, "https://api.example.com")
	}
	if len(report.Findings) != len(fixtures) {
		t.Errorf("len(Findings) = %d, want %d", len(report.Findings), len(fixtures))
	}
}

func TestBuilderIdempotent(t *testing.T) {
	b := reportx.NewBuilder()
	b.Tool("A", "1").Tool("B", "2")
	report, err := b.Build(context.Background())
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if report.ToolName != "B" {
		t.Errorf("ToolName = %q, want %q", report.ToolName, "B")
	}
}

func TestReportSeverityCounts(t *testing.T) {
	report := &reportx.Report{
		Findings: []reportx.Finding{
			{Severity: reportx.SeverityCritical},
			{Severity: reportx.SeverityCritical},
			{Severity: reportx.SeverityHigh},
			{Severity: reportx.SeverityLow},
		},
	}
	counts := report.SeverityCounts()
	if counts[reportx.SeverityCritical] != 2 {
		t.Errorf("critical count = %d, want 2", counts[reportx.SeverityCritical])
	}
	if counts[reportx.SeverityHigh] != 1 {
		t.Errorf("high count = %d, want 1", counts[reportx.SeverityHigh])
	}
}

func TestReportFindingsByStatus(t *testing.T) {
	fixtures := testdata.Fixtures()
	report := &reportx.Report{Findings: fixtures}
	active := report.FindingsByStatus(reportx.StatusActive)
	if len(active) == 0 {
		t.Error("expected some active findings")
	}
}

func TestReportFindingsBySeverity(t *testing.T) {
	fixtures := testdata.Fixtures()
	report := &reportx.Report{Findings: fixtures}
	critical := report.FindingsBySeverity(reportx.SeverityCritical)
	if len(critical) == 0 {
		t.Error("expected some critical findings")
	}
}

func TestBuilderWithEnrichAndDedup(t *testing.T) {
	fixtures := testdata.Fixtures()
	report, err := reportx.NewBuilder().
		Tool("TestScanner", "2.0.0").
		Target("https://api.example.com").
		ScanDate(time.Now()).
		Findings(fixtures).
		Enrich(enrich.EnrichAll).
		Deduplicate(dedup.Deduplicate).
		Build(context.Background())
	if err != nil {
		t.Fatalf("Build() with Enrich+Deduplicate error: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Error("expected findings after dedup")
	}
}

func TestBuilderEnrichWorks(t *testing.T) {
	fixtures := testdata.Fixtures()
	report, err := reportx.NewBuilder().
		Tool("T", "1").
		Findings(fixtures).
		Enrich(enrich.EnrichAll).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.CWEID == "" {
			continue
		}
		if f.CWEName == "" {
			t.Errorf("finding %q: CWEName not enriched", f.ID)
		}
	}
}

func TestBuilderDedupWorks(t *testing.T) {
	fixtures := testdata.Fixtures()
	report, err := reportx.NewBuilder().
		Tool("T", "1").
		Findings(fixtures).
		Deduplicate(dedup.Deduplicate).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) >= len(fixtures) {
		t.Errorf("Deduplicate did not reduce count: before=%d after=%d", len(fixtures), len(report.Findings))
	}
}

func TestBuilderDoesNotMutateInput(t *testing.T) {
	fixtures := testdata.Fixtures()
	original := make([]reportx.Finding, len(fixtures))
	copy(original, fixtures)

	_, err := reportx.NewBuilder().
		Findings(fixtures).
		Enrich(enrich.EnrichAll).
		Deduplicate(dedup.Deduplicate).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range fixtures {
		if f.CWEName != original[i].CWEName {
			t.Errorf("input slice was mutated at index %d", i)
		}
	}
}
