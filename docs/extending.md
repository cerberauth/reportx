# Extending reportx

## Custom formatter

Implement `format.Formatter` (or the identical `reportx.Formatter`) to add a new output format:

```go
package myformat

import (
    "bytes"
    "fmt"

    "github.com/cerberauth/reportx"
)

type CSVFormatter struct{}

func (f *CSVFormatter) Format(r *reportx.Report) ([]byte, error) {
    var buf bytes.Buffer
    buf.WriteString("id,title,severity,url,cwe\n")
    for _, finding := range r.Findings {
        fmt.Fprintf(&buf, "%s,%s,%s,%s,%s\n",
            finding.ID, finding.Title, string(finding.Severity),
            finding.URL, finding.CWEID,
        )
    }
    return buf.Bytes(), nil
}

func (f *CSVFormatter) MediaType() string     { return "text/csv" }
func (f *CSVFormatter) FileExtension() string { return ".csv" }
```

Use it anywhere a `Formatter` is accepted:

```go
// Format to bytes
data, err := new(myformat.CSVFormatter).Format(report)

// Write to file
err = report.WriteToFile(ctx, "findings.csv", new(myformat.CSVFormatter))

// Send via transport
err = report.Send(ctx, tr, new(myformat.CSVFormatter))
```

---

## Custom transport

Implement `transport.Transport` to send reports to any destination:

```go
package mytransport

import (
    "context"
    "github.com/cerberauth/reportx"
)

type SlackTransport struct {
    WebhookURL string
}

func (t *SlackTransport) Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error {
    data, err := f.Format(r)
    if err != nil {
        return err
    }
    // POST data to Slack webhook...
    return nil
}
```

Use it via `report.Send()`:

```go
err := report.Send(ctx, &mytransport.SlackTransport{WebhookURL: url}, format.NewJSONFormatter())
```

---

## Custom enrichment

Pass any function with signature `func([]Finding) []Finding` to `Builder.Enrich()`:

```go
func myEnrich(findings []reportx.Finding) []reportx.Finding {
    out := make([]reportx.Finding, len(findings))
    copy(out, findings)
    for i := range out {
        if out[i].CWEID == "CWE-89" && out[i].OwaspTop10 == "" {
            out[i].OwaspTop10 = "A03:2021 – Injection"
        }
    }
    return out
}

report, err := reportx.NewBuilder().
    Findings(findings).
    Enrich(myEnrich).
    Build(ctx)
```

---

## Custom deduplication

Pass any function with signature `func([]Finding) []Finding` to `Builder.Deduplicate()`:

```go
func myDedup(findings []reportx.Finding) []reportx.Finding {
    // your deduplication logic
    return findings
}

report, err := reportx.NewBuilder().
    Findings(findings).
    Deduplicate(myDedup).
    Build(ctx)
```
