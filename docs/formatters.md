# Formatters

All formatters live in the `format` sub-package and implement `reportx.Formatter`.

## Available formats

| Constructor | Format | MediaType | FileExtension |
|-------------|--------|-----------|---------------|
| `NewJSONFormatter()` | JSON | `application/json` | `.json` |
| `NewJSONLFormatter()` | JSONL | `application/x-ndjson` | `.jsonl` |
| `NewSARIFFormatter()` | SARIF 2.1.0 | `application/sarif+json` | `.sarif.json` |
| `NewMarkdownFormatter()` | Markdown | `text/markdown` | `.md` |
| `NewMarkdownFormatterWithReferrerTag(tag)` | Markdown, URLs tagged with `?ref=tag` | `text/markdown` | `.md` |
| `NewHTMLFormatter()` | HTML | `text/html` | `.html` |
| `NewHTMLFormatterWithReferrerTag(tag)` | HTML, URLs tagged with `?ref=tag` | `text/html` | `.html` |
| `NewTerminalFormatter()` | Terminal | `text/plain` | `.txt` |
| `NewTerminalFormatterNoColor()` | Terminal (no ANSI) | `text/plain` | `.txt` |
| `NewTerminalFormatterWithReferrerTag(tag)` | Terminal, URLs tagged with `?ref=tag` | `text/plain` | `.txt` |

---

## JSON

Produces a single JSON object with a `metadata` envelope and a `findings` array.

```go
data, err := format.NewJSONFormatter().Format(report)
```

**Output shape:**

```json
{
  "metadata": {
    "title": "Nightly scan",
    "tool": "MyScanner",
    "version": "1.0.0",
    "scan_date": "2024-11-12T14:00:00Z",
    "target": "https://api.example.com",
    "total": 3,
    "by_severity": { "critical": 1, "high": 2 },
    "generated_by": "cerberauth/reportx"
  },
  "findings": [...]
}
```

Best for: REST APIs, dashboards, programmatic processing.

---

## JSONL

One JSON object per line (newline-delimited JSON). Each line is a `Finding`.

```go
data, err := format.NewJSONLFormatter().Format(report)
```

Best for: streaming pipelines, feeding to `jq`, SIEM ingestion.

---

## SARIF

Valid [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output. Compatible with GitHub Code Scanning and most IDE integrations.

```go
data, err := format.NewSARIFFormatter().Format(report)
```

Severity mapping:

| reportx | SARIF level |
|---------|-------------|
| critical, high | `error` |
| medium | `warning` |
| low, info | `note` |

Best for: GitHub Code Scanning, Azure DevOps, IDE security plugins.

---

## Markdown

Groups findings by severity (critical → info). Each finding renders as a `###` heading with a metadata table and collapsible `<details>` block for evidence.

```go
data, err := format.NewMarkdownFormatter().Format(report)
```

Best for: PR comments, GitHub issues, wikis.

### Referrer tagging

Set a referrer tag to know when someone clicks a finding's `URL` from this report — the formatter appends `?ref=<tag>` (merged into any existing query string) to `Finding.URL` before rendering it:

```go
data, err := format.NewMarkdownFormatterWithReferrerTag("weekly-scan").Format(report)
```

Off by default — `Finding.URL` is rendered unchanged unless a tag is set. This only affects Markdown, HTML, and Terminal output; JSON, JSONL, and SARIF always emit the original `Finding.URL`.

---

## HTML

Self-contained HTML file — no external CSS or JS. Includes a summary badge bar and collapsible finding cards grouped by severity. Print-friendly via embedded print stylesheet.

```go
data, err := format.NewHTMLFormatter().Format(report)
```

Best for: standalone reports, email attachments, PDF export via browser print.

Supports the same [referrer tagging](#referrer-tagging) as Markdown, via `NewHTMLFormatterWithReferrerTag(tag)`.

---

## Terminal

ANSI-colored output for human reading in a terminal. Severity labels are color-coded:

| Severity | Color |
|----------|-------|
| critical | bold red |
| high | red |
| medium | yellow |
| low | cyan |
| info | blue |

```go
// With ANSI colors
f := format.NewTerminalFormatter()

// Plain text, no escape codes (e.g. for piping to a file)
f := format.NewTerminalFormatterNoColor()
```

Supports the same [referrer tagging](#referrer-tagging) as Markdown, via `NewTerminalFormatterWithReferrerTag(tag)`. Combine with no-color by constructing `&format.TerminalFormatter{NoColor: true, ReferrerTag: "weekly-scan"}` directly.

---

## Picking a formatter by name

Use `format.NewFormatter(name string)` to resolve a formatter from a string — useful when the format comes from a flag or config file.

```go
f, err := format.NewFormatter("sarif")  // returns *SARIFFormatter
```

Valid names: `json`, `jsonl`, `sarif`, `markdown` (alias: `md`), `html`, `terminal` (aliases: `text`, `plain`).

---

## CLIFlags helper

`format.CLIFlags` integrates format selection, output path, and color control into a `flag.FlagSet`. Use it when building a CLI tool on top of reportx.

```go
flags := format.RegisterFlags(flag.CommandLine)
flag.Parse()

formatter, err := flags.Formatter()    // resolves format + NoColor
writer, close, err := flags.Writer()  // os.Stdout or a file
defer close()

report.WriteTo(ctx, writer, formatter)
```

Registered flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-format` | `terminal` | `json \| jsonl \| sarif \| markdown \| html \| terminal` |
| `-output` | `""` (stdout) | file path to write the report |
| `-no-color` | `false` | disable ANSI colors in terminal output |
