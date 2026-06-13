# Deduplication

The `dedup` sub-package computes stable fingerprints and removes duplicate findings.

## Via Builder

```go
import "github.com/cerberauth/reportx/dedup"

report, err := reportx.NewBuilder().
    Findings(findings).
    Deduplicate(dedup.Deduplicate).
    Build(ctx)
```

## Directly on a slice

```go
deduped := dedup.Deduplicate(findings)
```

The input slice is not modified. Findings with pre-existing `FingerprintHash` values are used as-is; fingerprints are only computed for findings where `FingerprintHash` is empty.

## Fingerprint inputs

A SHA-256 fingerprint is computed from three fields, all normalized to lowercase:

| Input | Normalization |
|-------|---------------|
| `CWEID` | lowercased (e.g. `cwe-89`) |
| `URL` | scheme + host + path, query string and fragment stripped, trailing slash removed |
| `Parameter` | trimmed |

Two findings are considered duplicates when all three match — regardless of title, description, severity, evidence, or scanner metadata.

**Examples:**

```
CWE-89 + https://api.example.com/login?foo=1 + username
CWE-89 + https://api.example.com/login + username
→ same fingerprint (query string ignored)

CWE-89 + https://api.example.com/login + username
CWE-89 + https://api.example.com/login + password
→ different fingerprints (different parameter)
```

## Deduplication order

When duplicates are found, the **first occurrence** by index is kept. Subsequent duplicates are dropped.

## Computing a fingerprint without deduplicating

```go
hash := dedup.Fingerprint(&finding)
```

Useful for pre-stamping findings before merging results from multiple scanners.

## When to skip deduplication

- Your scanner already deduplicates internally.
- You intentionally want multiple findings per endpoint (e.g. to track each occurrence separately).

Simply omit `.Deduplicate(dedup.Deduplicate)` from the builder chain.
