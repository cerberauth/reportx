# reportx documentation

Go library for transforming raw DAST tool findings into standardized report output. Import it into OWASP ZAP wrappers, Nuclei post-processors, or custom scanners.

```
go get github.com/cerberauth/reportx
```

## Guides

- [API Reference](api-reference.md) — `Finding`, `Report`, `Builder`, `Formatter`, `Transport`
- [Formatters](formatters.md) — JSON, JSONL, SARIF, Markdown, HTML, Terminal, CLIFlags
- [Transports](transports.md) — `FSTransport`, `HTTPTransport`, custom transports
- [CWE Enrichment](enrichment.md) — auto-fill `CWEName` and `OwaspTop10`
- [Deduplication](deduplication.md) — fingerprinting and duplicate removal
- [CVSS Scoring](cvss.md) — CVSS 3.1 and 4.0 base score calculation
- [OpenTelemetry](otel.md) — spans, attributes, setup
- [Extending](extending.md) — custom formatters, transports, enrichment, dedup

## Quick start

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/cerberauth/reportx"
    "github.com/cerberauth/reportx/dedup"
    "github.com/cerberauth/reportx/enrich"
    "github.com/cerberauth/reportx/format"
)

func main() {
    ctx := context.Background()

    findings := []reportx.Finding{
        {
            Title:       "SQL Injection",
            Severity:    reportx.SeverityCritical,
            CWEID:       "CWE-89",
            URL:         "https://api.example.com/users",
            Parameter:   "id",
            Description: "User-controlled input passed to SQL query.",
            Remediation: "Use parameterized queries.",
            Status:      reportx.StatusActive,
        },
    }

    report, err := reportx.NewBuilder().
        Tool("MyScanner", "1.0.0").
        Target("https://api.example.com").
        Title("Nightly scan").
        Findings(findings).
        Enrich(enrich.EnrichAll).
        Deduplicate(dedup.Deduplicate).
        Build(ctx)
    if err != nil {
        log.Fatal(err)
    }

    if err := report.WriteTo(ctx, os.Stdout, format.NewSARIFFormatter()); err != nil {
        log.Fatal(err)
    }
}
```

## Sub-packages

| Package | Purpose |
|---------|---------|
| `github.com/cerberauth/reportx` | Core types: `Finding`, `Report`, `Builder` |
| `github.com/cerberauth/reportx/format` | All formatters + `CLIFlags` helper |
| `github.com/cerberauth/reportx/transport` | `FSTransport`, `HTTPTransport` |
| `github.com/cerberauth/reportx/enrich` | CWE name and OWASP Top 10 enrichment |
| `github.com/cerberauth/reportx/dedup` | Fingerprinting and deduplication |
| `github.com/cerberauth/reportx/score` | CVSS 3.1 and 4.0 score calculation |
