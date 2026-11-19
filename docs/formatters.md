# Formatters

All formatters live in the `format` sub-package and implement `reportx.Formatter`.

## Available formats

| Constructor | Format | MediaType | FileExtension |
|-------------|--------|-----------|---------------|
| `NewJSONFormatter()` | JSON | `application/json` | `.json` |
| `NewYAMLFormatter()` | YAML | `application/yaml` | `.yaml` |
| `NewJSONLFormatter()` | JSONL | `application/x-ndjson` | `.jsonl` |
| `NewSARIFFormatter()` | SARIF 2.1.0 | `application/sarif+json` | `.sarif.json` |
| `NewMarkdownFormatter()` | Markdown | `text/markdown` | `.md` |
| `NewMarkdownFormatterWithReferrerTag(tag)` | Markdown, URLs tagged with `?ref=tag` | `text/markdown` | `.md` |
| `NewHTMLFormatter()` | HTML | `text/html` | `.html` |
| `NewHTMLFormatterWithReferrerTag(tag)` | HTML, URLs tagged with `?ref=tag` | `text/html` | `.html` |
| `NewTerminalFormatter()` | Terminal | `text/plain` | `.txt` |
| `NewTerminalFormatterNoColor()` | Terminal (no ANSI) | `text/plain` | `.txt` |
| `NewTerminalFormatterWithReferrerTag(tag)` | Terminal, URLs tagged with `?ref=tag` | `text/plain` | `.txt` |
| `NewJUnitFormatter()` | JUnit XML | `application/xml` | `.junit.xml` |
| `NewJUnitFormatterWithThreshold(sev)` | JUnit XML, failing from `sev` upwards | `application/xml` | `.junit.xml` |
| `NewGitLabFormatter()` | GitLab DAST security report | `application/json` | `.gl-dast-report.json` |

---

## JSON

Produces a single JSON object with a `metadata` envelope and a `findings` array.

```go
data, err := format.NewJSONFormatter().Format(report)
```

**Output shape:**

```json
{
  "$schema": "https://schemas.cerberauth.com/reportx/v0.5.0/report.schema.json",
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

Output carries a `$schema` field pointing at the published [JSON Schema](https://schemas.cerberauth.com/reportx/v0.5.0/report.schema.json) — editors and validators can use it directly.

When the report has scan errors or coverage, top-level `errors` (`check_id`, `resource`, `message`) and `coverage` (`run`, `skipped`, `errored`) objects are added; they are omitted otherwise.

A finding's `confidence` (`confirmed`, `firm` or `tentative`) is emitted when set, and omitted otherwise. The same applies to YAML and JSONL, and the terminal, Markdown and HTML formatters show it as a "Confidence" field.

Best for: REST APIs, dashboards, programmatic processing.

---

## YAML

Same shape as JSON — `metadata` envelope plus `findings` array — marshaled to YAML instead. Carries the same `$schema` field.

```go
data, err := format.NewYAMLFormatter().Format(report)
```

Best for: config-driven pipelines, GitOps workflows, human-edited reports.

---

## JSONL

One JSON object per line (newline-delimited JSON). Each line is a `Finding`, tagged with its own `$schema` field pointing at the [Finding schema](https://schemas.cerberauth.com/reportx/v0.5.0/finding.schema.json).

```go
data, err := format.NewJSONLFormatter().Format(report)
```

When the report has scan errors or coverage, a final `{"type": "scan_summary", "errors": [...], "coverage": {...}}` line follows the findings. Finding lines have no `type` key.

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

Confidence maps to the result's `rank` (confirmed 100, firm 70, tentative 30) and `properties.confidence`, so code-scanning views can sort on it; both are omitted when confidence is unspecified.

Scan errors become `invocations[0].toolExecutionNotifications` (level `error`, `associatedRule.id` = check ID, location = resource) and `executionSuccessful` is `false`; coverage counts go to the run's `properties.coverage`.

Best for: GitHub Code Scanning, Azure DevOps, IDE security plugins.

---

## JUnit XML

JUnit XML for CI systems that render test results (GitLab, Jenkins, Azure DevOps, CircleCI, ...). One `<testsuite>` named after the report target, with:

- one `<testcase>` per finding, with `classname` the CWE ID (falling back to the finding ID) and `name` the title plus affected URL and parameter;
- one `<testcase>` with an `<error>` per scan error;
- when the report has [coverage](api-reference.md#errors-and-coverage), one passing `<testcase>` for each check that ran without producing a finding (`Coverage.Run` minus the number of findings).

JUnit has no severity concept, so the formatter's `FailOn` option sets the failing threshold: findings at or above it get a `<failure message="title" type="severity">` whose body carries the title, severity, remediation and other context. Findings below it are passing test cases. The report has no fail threshold of its own yet, so the default (`NewJUnitFormatter()`) fails every finding. Findings that are not `active` (false positive, accepted risk, mitigated) are reported as `<skipped>`.

```go
// Fail the build only on high and critical findings
data, err := format.NewJUnitFormatterWithThreshold(reportx.SeverityHigh).Format(report)
```

Best for: CI test-result tabs and trend graphs.

---

## GitLab security report

A GitLab DAST report, so findings appear in merge requests and the security dashboard when the file is published as a `dast` report artifact:

```yaml
artifacts:
  reports:
    dast: gl-dast-report.json
```

```go
data, err := format.NewGitLabFormatter().Format(report)
```

The output conforms to version **15.2.5** of GitLab's [`dast-report-format.json`](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/v15.2.5/dist/dast-report-format.json) (`format.GitLabSchemaVersion`); tests validate it against a pinned copy of that schema.

| reportx | GitLab |
|---------|--------|
| severity | `severity` (`Critical`, `High`, `Medium`, `Low`, `Info`; anything else `Unknown`) |
| `CWEID`, `OwaspTop10` | `identifiers` (a finding with neither gets one from its ID) |
| `URL`, `Parameter`, HTTP evidence method | `location` (`hostname`, `path`, `param`, `method`) |
| `Remediation` | `solution` |
| `References` | `links` |
| `CVSS31Vector`, `CVSS40Vector` | `cvss_vectors` |
| structured HTTP evidence | `evidence.request` / `evidence.response` |
| `StatusFalsePositive` | `flags` (`flagged-as-likely-false-positive`) |
| scan errors | `scan.messages` (level `warn`), and `scan.status` becomes `failure` |

`scan.scanned_resources` lists the report target and every finding URL.

Best for: GitLab merge request widgets and the vulnerability report.

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

Valid names: `json`, `yaml` (alias: `yml`), `jsonl`, `sarif`, `markdown` (alias: `md`), `html`, `terminal` (aliases: `text`, `plain`), `junit`, `gitlab`.

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
| `-format` | `terminal` | `json \| yaml \| jsonl \| sarif \| markdown \| html \| terminal \| junit \| gitlab` |
| `-output` | `""` (stdout) | file path to write the report |
| `-no-color` | `false` | disable ANSI colors in terminal output |
