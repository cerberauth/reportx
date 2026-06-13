# CVSS Scoring

The `score` sub-package computes CVSS base scores from vector strings and maps them to severity labels.

## CVSS 3.1

```go
import "github.com/cerberauth/reportx/score"

s, err := score.CalculateV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
// s = 9.8
```

## CVSS 4.0

```go
s, err := score.CalculateV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
// s = 10.0
```

Both functions return `(float64, error)`. An error is returned for malformed or unrecognized vector strings.

## Score → Severity label

```go
severity := score.Label(s)
```

| Score range | Severity |
|-------------|----------|
| ≥ 9.0 | `SeverityCritical` |
| 7.0 – 8.9 | `SeverityHigh` |
| 4.0 – 6.9 | `SeverityMedium` |
| 0.1 – 3.9 | `SeverityLow` |
| 0.0 | `SeverityInfo` |

## Typical usage

Score the finding, then derive severity and store the vector:

```go
vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
s, err := score.CalculateV31(vec)
if err != nil {
    log.Fatal(err)
}

finding := reportx.Finding{
    Title:        "SQL Injection",
    Severity:     score.Label(s),
    CVSS31Score:  s,
    CVSS31Vector: vec,
    // ...
}
```
