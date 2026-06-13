# API Reference

## Package `reportx`

### Finding

`Finding` is the core data type. All fields are optional except `Title` and `Severity`.

```go
type Finding struct {
    // Identity
    ID    string   // optional; stable identifier across scans
    Title string   // short human-readable label

    // Risk scoring
    Severity     Severity // critical | high | medium | low | info
    CVSS31Score  float64  // base score 0–10
    CVSS31Vector string   // e.g. "CVSS:3.1/AV:N/AC:L/..."
    CVSS40Score  float64  // base score 0–10
    CVSS40Vector string   // e.g. "CVSS:4.0/AV:N/AC:L/..."

    // Classification
    CWEID      string // e.g. "CWE-89"; filled by scanner
    CWEName    string // e.g. "SQL Injection"; filled by Enrich()
    OwaspTop10 string // e.g. "A03:2021 – Injection"; filled by Enrich()

    // Location
    URL       string // endpoint URL
    Parameter string // query/body parameter, header name, etc.

    // Evidence
    Evidence Evidence // raw or structured HTTP traffic

    // Narrative
    Description string // what was found and why it matters
    Remediation string // how to fix it

    // Lifecycle
    FirstSeen       time.Time
    LastSeen        time.Time
    Status          Status // active | false_positive | accepted_risk | mitigated
    FingerprintHash string // SHA-256 hex; set by Deduplicate() or manually

    // Metadata
    Tags  []string          // free-form labels, e.g. ["injection", "auth"]
    Extra map[string]string // scanner-specific key/value pairs
}
```

#### Severity constants

```go
SeverityCritical Severity = "critical"
SeverityHigh     Severity = "high"
SeverityMedium   Severity = "medium"
SeverityLow      Severity = "low"
SeverityInfo     Severity = "info"
```

#### Status constants

```go
StatusActive        Status = "active"
StatusFalsePositive Status = "false_positive"
StatusAcceptedRisk  Status = "accepted_risk"
StatusMitigated     Status = "mitigated"
```

---

### Evidence

Structured HTTP traffic attached to a finding. Either use the raw string fields or the structured fields — both are supported.

```go
type Evidence struct {
    // Raw strings
    RawRequest  string // full HTTP request as text
    RawResponse string // full HTTP response as text

    // Structured
    RequestMethod   string
    RequestURL      string
    RequestBody     []byte
    ResponseStatus  int
    ResponseHeaders map[string][]string
    ResponseBody    []byte
}
```

Helper methods:

```go
func (e Evidence) IsEmpty() bool        // true when no field is set
func (e Evidence) HasStructured() bool  // true when any structured field is set
```

---

### Report

```go
type Report struct {
    Title       string
    ScanDate    time.Time
    ToolName    string
    ToolVersion string
    Target      string
    Findings    []Finding
}
```

#### Methods

```go
// Write serialized output to any io.Writer.
func (r *Report) WriteTo(ctx context.Context, w io.Writer, f Formatter) error

// Write serialized output to a file at path (creates or truncates).
func (r *Report) WriteToFile(ctx context.Context, path string, f Formatter) error

// Send via a Transport.
func (r *Report) Send(ctx context.Context, t Transport, f Formatter) error

// Count findings by severity.
func (r *Report) SeverityCounts() map[Severity]int

// Filter findings to a single severity band.
func (r *Report) FindingsBySeverity(s Severity) []Finding
```

---

### Builder

Fluent builder for constructing a `Report`. All methods return `*Builder` for chaining.

```go
func NewBuilder() *Builder

func (b *Builder) Title(title string) *Builder
func (b *Builder) Tool(name, version string) *Builder
func (b *Builder) Target(target string) *Builder
func (b *Builder) Findings(findings []Finding) *Builder
func (b *Builder) ScanDate(t time.Time) *Builder

// Enrich fills CWEName and OwaspTop10 on each finding.
// Pass enrich.EnrichAll from the enrich sub-package.
func (b *Builder) Enrich(fn EnrichFunc) *Builder

// Deduplicate computes fingerprints and drops duplicates.
// Pass dedup.Deduplicate from the dedup sub-package.
func (b *Builder) Deduplicate(fn DedupFunc) *Builder

// Build validates input and constructs the Report.
// ScanDate defaults to time.Now() when not set.
func (b *Builder) Build(ctx context.Context) (*Report, error)
```

**Example:**

```go
report, err := reportx.NewBuilder().
    Tool("MyScanner", "1.0.0").
    Target("https://api.example.com").
    Title("Nightly scan").
    Findings(findings).
    Enrich(enrich.EnrichAll).
    Deduplicate(dedup.Deduplicate).
    Build(ctx)
```

---

### Formatter interface

```go
type Formatter interface {
    Format(r *Report) ([]byte, error)
    MediaType() string
    FileExtension() string
}
```

---

### Transport interface

```go
type Transport interface {
    Send(ctx context.Context, r *Report, f Formatter) error
}
```
