package enrich_test

import (
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/internal/testdata"
)

func TestLookupNormalization(t *testing.T) {
	forms := []string{"CWE-89", "cwe-89", "89"}
	for _, id := range forms {
		r, ok := enrich.Lookup(id)
		if !ok {
			t.Errorf("Lookup(%q) not found", id)
			continue
		}
		if r.ID != "CWE-89" {
			t.Errorf("Lookup(%q).ID = %q, want CWE-89", id, r.ID)
		}
		if r.ShortName == "" && r.Name == "" {
			t.Errorf("Lookup(%q) has empty name", id)
		}
		if r.OWASP2021 == "" {
			t.Errorf("Lookup(%q).OWASP2021 is empty", id)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	_, ok := enrich.Lookup("CWE-9999")
	if ok {
		t.Error("Lookup(CWE-9999) should return false")
	}
}

func TestDefaultEnricher(t *testing.T) {
	e := enrich.NewDefaultEnricher()
	fixtures := testdata.Fixtures()
	for i := range fixtures {
		f := &fixtures[i]
		if err := e.Enrich(f); err != nil {
			t.Fatalf("Enrich() error: %v", err)
		}
	}
	for _, f := range fixtures {
		if f.CWEID == "" {
			continue
		}
		if f.CWEName == "" {
			t.Errorf("finding %q with CWEID %q has empty CWEName after enrich", f.ID, f.CWEID)
		}
		if f.OwaspTop10 == "" {
			t.Errorf("finding %q with CWEID %q has empty OwaspTop10 after enrich", f.ID, f.CWEID)
		}
	}
}

func TestEnricherMissingCWE(t *testing.T) {
	e := enrich.NewDefaultEnricher()
	f := &reportx.Finding{ID: "test-no-cwe"}
	if err := e.Enrich(f); err != nil {
		t.Fatalf("Enrich() with empty CWEID returned error: %v", err)
	}
	if f.CWEName != "" || f.OwaspTop10 != "" {
		t.Error("expected empty CWEName and OwaspTop10 when CWEID is empty")
	}
}

func TestEnricherUnknownCWE(t *testing.T) {
	e := enrich.NewDefaultEnricher()
	f := &reportx.Finding{ID: "test", CWEID: "CWE-9999"}
	if err := e.Enrich(f); err != nil {
		t.Fatalf("Enrich() with unknown CWE returned error: %v", err)
	}
}

func TestEnrichAll(t *testing.T) {
	fixtures := testdata.Fixtures()
	enriched := enrich.EnrichAll(fixtures)
	if len(enriched) != len(fixtures) {
		t.Errorf("EnrichAll length mismatch: got %d, want %d", len(enriched), len(fixtures))
	}
	original := testdata.Fixtures()
	for i, f := range original {
		if f.CWEName != fixtures[i].CWEName {
			t.Errorf("original finding %q was mutated by EnrichAll", f.ID)
		}
	}
}
