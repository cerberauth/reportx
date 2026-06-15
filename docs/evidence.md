# Evidence

The `evidence` sub-package provides concrete evidence types that attach to a `Finding`. Evidence is polymorphic — `Finding.Evidence` is an interface, so you can use the built-in types or implement your own.

```go
import "github.com/cerberauth/reportx/evidence"
```

---

## HTTPEvidence

Use when the finding was discovered via an HTTP request/response.

```go
type HTTPEvidence struct {
    // Raw strings — full HTTP message text
    RawRequest  string
    RawResponse string

    // Structured fields
    RequestMethod   string
    RequestURL      string
    RequestBody     []byte
    ResponseStatus  int
    ResponseHeaders map[string][]string
    ResponseBody    []byte
}
```

You can populate raw strings, structured fields, or both. Formatters render structured fields (method, URL, status, headers, body) when any are set; otherwise they fall back to the raw strings.

### Example — raw only

```go
finding.Evidence = &evidence.HTTPEvidence{
    RawRequest:  "GET /users?id=1' HTTP/1.1\r\nHost: api.example.com",
    RawResponse: "HTTP/1.1 500 Internal Server Error\r\n\r\nSQLite error: syntax error",
}
```

### Example — structured

```go
finding.Evidence = &evidence.HTTPEvidence{
    RequestMethod:  "POST",
    RequestURL:     "https://api.example.com/auth/login",
    RequestBody:    []byte(`{"username":"' OR 1=1--","password":"x"}`),
    ResponseStatus: 500,
    ResponseBody:   []byte("SQLite error: near \"OR\": syntax error"),
}
```

### Helper methods

```go
func (e *HTTPEvidence) IsEmpty() bool       // true when all fields are zero
func (e *HTTPEvidence) HasStructured() bool // true when any structured field is set
```

---

## CustomEvidence

Use for any evidence that is not an HTTP exchange — binary diff, config snippet, log line, timing measurement, etc.

```go
type CustomEvidence struct {
    Data map[string]any
}
```

### Example

```go
finding.Evidence = &evidence.CustomEvidence{
    Data: map[string]any{
        "payload":       `{"__proto__":{"admin":true}}`,
        "response_time": "4.2s",
        "notes":         "Server took 4x longer with prototype pollution payload",
    },
}
```

Formatters render `CustomEvidence` as a key-value table (HTML, Markdown) or space-separated `key=value` pairs (terminal).

### Helper methods

```go
func (e *CustomEvidence) IsEmpty() bool // true when Data is nil or empty
```

---

## Custom evidence types

`Finding.Evidence` accepts any type that satisfies:

```go
type Evidence interface {
    IsEmpty() bool
}
```

Implement this interface to attach domain-specific evidence. Formatters ignore unknown types by default (no panic, no output), so rendering requires a custom formatter or a formatter contribution.

```go
type BinaryDiffEvidence struct {
    Before []byte
    After  []byte
}

func (e *BinaryDiffEvidence) IsEmpty() bool {
    return len(e.Before) == 0 && len(e.After) == 0
}

finding.Evidence = &BinaryDiffEvidence{
    Before: originalBytes,
    After:  mutatedBytes,
}
```

---

## Formatter output

| Formatter | HTTPEvidence | CustomEvidence |
|-----------|-------------|----------------|
| JSON | `evidence` object with HTTP fields | `evidence` object with `Data` keys |
| HTML | `<details>` with `<pre>` blocks | `<details>` with `<dl>` key-value list |
| Markdown | `<details>` with ` ```http ` blocks | `<details>` with markdown table |
| Terminal | `Method URL → Status` one-liner | `key=value` pairs on one line |
| SARIF | not included | not included |
