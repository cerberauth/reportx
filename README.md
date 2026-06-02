# reportx

A Go library for transforming raw DAST tool findings into standardized report output.
Import it into OWASP ZAP wrappers, Nuclei post-processors, or custom scanners.

## Installation

```bash
go get github.com/cerberauth/reportx
```

## Quick start

```go
package main

import (
    "log"
    "os"

    "github.com/cerberauth/reportx"
    "github.com/cerberauth/reportx/format"
)

func main() {
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
        Enrich().      // auto-fill CWEName + OwaspTop10
        Deduplicate(). // compute + apply fingerprints
        Build()
    if err != nil {
        log.Fatal(err)
    }

    data, err := format.NewSARIFFormatter().Format(report)
    if err != nil {
        log.Fatal(err)
    }
    os.Stdout.Write(data)
}
```

## Formatters

| Format | MediaType | FileExtension | Best used for |
|--------|-----------|---------------|---------------|
| JSON | `application/json` | `.json` | REST APIs, dashboards |
| JSONL | `application/x-ndjson` | `.jsonl` | Streaming pipelines, `jq` |
| SARIF | `application/sarif+json` | `.sarif.json` | GitHub Code Scanning, IDEs |
| Markdown | `text/markdown` | `.md` | PR comments, wikis |
| HTML | `text/html` | `.html` | Standalone reports, email |

### JSON

```go
data, err := format.NewJSONFormatter().Format(report)
// Writes: { "metadata": {...}, "findings": [...] }
```

### JSONL

```go
data, err := format.NewJSONLFormatter().Format(report)
// One JSON object per line — pipe to jq or a SIEM
```

### SARIF

```go
data, err := format.NewSARIFFormatter().Format(report)
// Valid SARIF 2.1.0 — upload to GitHub Code Scanning
```

### Markdown

```go
data, err := format.NewMarkdownFormatter().Format(report)
// Post as a PR comment or embed in a wiki page
```

### HTML

```go
data, err := format.NewHTMLFormatter().Format(report)
// Self-contained HTML file — no external CSS or JS
// Includes print stylesheet for clean PDF export
```

### Writing to a file

```go
err := report.WriteToFile("report.sarif.json", format.NewSARIFFormatter())
```

### Writing to any io.Writer

```go
err := report.WriteTo(os.Stdout, format.NewJSONFormatter())
```

## CVSS scoring

The `score` sub-package computes CVSS base scores from vector strings.

### CVSS 3.1

```go
import "github.com/cerberauth/reportx/score"

s, err := score.CalculateV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
// s = 9.8

severity := score.Label(s) // reportx.SeverityCritical
```

### CVSS 4.0

```go
s, err := score.CalculateV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
// s = 10.0
```

## Deduplication

`Builder.Deduplicate()` computes a stable SHA-256 fingerprint for every finding and drops duplicates, keeping the first occurrence by index.

**Fingerprint inputs** (all normalized to lowercase):
- `CWEID` — e.g. `cwe-89`
- `URL` — scheme + host + path, no query string or fragment, no trailing slash
- `Parameter` — trimmed

Two findings with the same CWE, endpoint, and parameter are considered duplicates regardless of their title, description, or evidence.

**Opt out** if your scanner already deduplicates, or if you intentionally want multiple findings per endpoint:

```go
report, err := reportx.NewBuilder().
    Findings(findings).
    // no .Deduplicate() call
    Build()
```

## CWE enrichment

`Builder.Enrich()` fills `Finding.CWEName` and `Finding.OwaspTop10` from an embedded CWE database (no network calls). It covers 20 common web vulnerabilities including CWE-89, CWE-79, CWE-22, CWE-352, CWE-918, and more.

Enrichment is a no-op when `Finding.CWEID` is empty or unknown — it never returns an error for missing data.

You can also enrich findings directly:

```go
import "github.com/cerberauth/reportx/enrich"

enriched := enrich.EnrichAll(findings) // returns new slice, original unchanged
```

## Extending reportx

Implement the `format.Formatter` interface to add a custom output format:

```go
package myformat

import "github.com/cerberauth/reportx"

type CSVFormatter struct{}

func (f *CSVFormatter) Format(r *reportx.Report) ([]byte, error) {
    var buf bytes.Buffer
    buf.WriteString("id,title,severity,url,cwe\n")
    for _, finding := range r.Findings {
        fmt.Fprintf(&buf, "%s,%s,%s,%s,%s\n",
            finding.ID, finding.Title, finding.Severity,
            finding.URL, finding.CWEID,
        )
    }
    return buf.Bytes(), nil
}

func (f *CSVFormatter) MediaType() string     { return "text/csv" }
func (f *CSVFormatter) FileExtension() string { return ".csv" }
```

Use it with any `Report`:

```go
data, err := new(myformat.CSVFormatter).Format(report)
```

Or write directly to a file:

```go
err := report.WriteToFile("findings.csv", new(myformat.CSVFormatter))
```

## License

See [LICENSE](LICENSE).
