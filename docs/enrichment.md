# CWE Enrichment

The `enrich` sub-package fills `Finding.CWEName` and `Finding.OwaspTop10` from an embedded database. No network calls are made.

## Via Builder

```go
import "github.com/cerberauth/reportx/enrich"

report, err := reportx.NewBuilder().
    Findings(findings).
    Enrich(enrich.EnrichAll).
    Build(ctx)
```

`enrich.EnrichAll` returns a new slice; the original slice is not modified.

## Directly on a slice

```go
enriched := enrich.EnrichAll(findings)
```

## What gets filled

For each finding where `CWEID` is set and recognized:

| Field | Filled with |
|-------|-------------|
| `CWEName` | Short name from the CWE database (e.g. `"SQL Injection"`) |
| `OwaspTop10` | OWASP Top 10 2021 category (e.g. `"A03:2021 – Injection"`) |

Fields that are already non-empty are left unchanged. Findings with an empty or unrecognized `CWEID` are passed through without error.

## Covered CWEs

The embedded database covers common web vulnerabilities including:

| CWE | Name |
|-----|------|
| CWE-79 | Cross-site Scripting (XSS) |
| CWE-89 | SQL Injection |
| CWE-22 | Path Traversal |
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-200 | Exposure of Sensitive Information |
| and ~15 more | — |

If your CWE is not in the embedded set, enrichment silently skips it. You can pre-set `CWEName` and `OwaspTop10` on findings you create manually — enrichment never overwrites existing values.

## Low-level API

```go
record, ok := enrich.Lookup("CWE-89")
if ok {
    fmt.Println(record.ShortName) // "SQL Injection"
    fmt.Println(record.OWASP2021) // "A03:2021 – Injection"
}
```
