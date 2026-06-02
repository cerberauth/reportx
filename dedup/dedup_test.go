package dedup_test

import (
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/dedup"
	"github.com/cerberauth/reportx/internal/testdata"
)

func TestFingerprintConsistency(t *testing.T) {
	fixtures := testdata.Fixtures()
	f1 := fixtures[0]
	f2 := fixtures[0]
	h1 := dedup.Fingerprint(&f1)
	h2 := dedup.Fingerprint(&f2)
	if h1 != h2 {
		t.Errorf("identical findings have different fingerprints: %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Error("Fingerprint returned empty string")
	}
}

func TestFingerprintSameCWEDifferentParam(t *testing.T) {
	f1 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/login", Parameter: "username"}
	f2 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/login", Parameter: "password"}
	if dedup.Fingerprint(&f1) == dedup.Fingerprint(&f2) {
		t.Error("different parameters should produce different fingerprints")
	}
}

func TestFingerprintURLTrailingSlash(t *testing.T) {
	f1 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/login", Parameter: "q"}
	f2 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/login/", Parameter: "q"}
	if dedup.Fingerprint(&f1) != dedup.Fingerprint(&f2) {
		t.Error("URL with and without trailing slash should produce same fingerprint")
	}
}

func TestFingerprintURLQueryString(t *testing.T) {
	f1 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/search", Parameter: "q"}
	f2 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/search?foo=bar&baz=1", Parameter: "q"}
	if dedup.Fingerprint(&f1) != dedup.Fingerprint(&f2) {
		t.Error("URL with and without query string should produce same fingerprint")
	}
}

func TestFingerprintCWEIDNormalization(t *testing.T) {
	f1 := reportx.Finding{CWEID: "CWE-89", URL: "https://api.example.com/login", Parameter: "id"}
	f2 := reportx.Finding{CWEID: "cwe-89", URL: "https://api.example.com/login", Parameter: "id"}
	if dedup.Fingerprint(&f1) != dedup.Fingerprint(&f2) {
		t.Error("CWE-89 and cwe-89 should produce same fingerprint")
	}
}

func TestDeduplicateRemovesDuplicates(t *testing.T) {
	findings := []reportx.Finding{
		{ID: "1", CWEID: "CWE-89", URL: "https://example.com/api", Parameter: "id"},
		{ID: "2", CWEID: "CWE-79", URL: "https://example.com/search", Parameter: "q"},
		{ID: "3", CWEID: "CWE-89", URL: "https://example.com/api", Parameter: "id"},
		{ID: "4", CWEID: "CWE-22", URL: "https://example.com/file", Parameter: "path"},
		{ID: "5", CWEID: "CWE-89", URL: "https://example.com/api", Parameter: "id"},
		{ID: "6", CWEID: "CWE-352", URL: "https://example.com/account", Parameter: ""},
		{ID: "7", CWEID: "CWE-79", URL: "https://example.com/search", Parameter: "q"},
		{ID: "8", CWEID: "CWE-200", URL: "https://example.com/profile", Parameter: ""},
		{ID: "9", CWEID: "CWE-918", URL: "https://example.com/webhook", Parameter: "url"},
		{ID: "10", CWEID: "CWE-22", URL: "https://example.com/file", Parameter: "path"},
	}
	deduped := dedup.Deduplicate(findings)
	if len(deduped) != 6 {
		t.Errorf("Deduplicate: got %d findings, want 6", len(deduped))
	}
	if deduped[0].ID != "1" {
		t.Errorf("first finding should be ID=1, got %q", deduped[0].ID)
	}
}

func TestDeduplicateDoesNotMutateInput(t *testing.T) {
	original := testdata.Fixtures()
	originalHashes := make([]string, len(original))
	for i := range original {
		originalHashes[i] = original[i].FingerprintHash
	}
	_ = dedup.Deduplicate(original)
	for i := range original {
		if original[i].FingerprintHash != originalHashes[i] {
			t.Errorf("Deduplicate mutated input finding[%d].FingerprintHash", i)
		}
	}
}

func TestDeduplicateSetsHash(t *testing.T) {
	fixtures := testdata.Fixtures()
	deduped := dedup.Deduplicate(fixtures)
	for _, f := range deduped {
		if f.FingerprintHash == "" {
			t.Errorf("finding %q has empty FingerprintHash after dedup", f.ID)
		}
	}
}
