# Transports

Transports send a formatted report to a destination. They implement `reportx.Transport` (or `transport.Transport` — the two interfaces are identical).

```go
type Transport interface {
    Send(ctx context.Context, r *Report, f Formatter) error
}
```

---

## FSTransport

Writes a formatted report to the filesystem.

```go
import "github.com/cerberauth/reportx/transport"

tr := transport.NewFSTransport("/var/reports")
err := report.Send(ctx, tr, format.NewSARIFFormatter())
// writes: /var/reports/report.sarif.json
```

**Fields:**

```go
type FSTransport struct {
    Dir      string // destination directory (created if missing)
    Filename string // optional; defaults to "report" + formatter.FileExtension()
}
```

Override the filename:

```go
tr := &transport.FSTransport{
    Dir:      "/var/reports",
    Filename: "2024-11-12-nightly.sarif.json",
}
```

FSTransport creates intermediate directories with `os.MkdirAll` and writes files with mode `0600`.

---

## HTTPTransport

POSTs a formatted report to a webhook URL.

```go
tr := transport.NewHTTPTransport("https://hooks.example.com/security-reports")
err := report.Send(ctx, tr, format.NewJSONFormatter())
```

**Fields:**

```go
type HTTPTransport struct {
    URL     string            // POST destination
    Headers map[string]string // extra request headers (e.g. Authorization)
    Client  *http.Client      // optional; defaults to http.DefaultClient
}
```

The `Content-Type` header is set automatically from the formatter's `MediaType()`. An `X-Generated-By: cerberauth/reportx` header is always added.

**Adding authentication:**

```go
tr := transport.NewHTTPTransport("https://hooks.example.com/reports")
tr.Headers = map[string]string{
    "Authorization": "Bearer " + token,
}
```

**Custom HTTP client** (e.g. timeouts, TLS config):

```go
tr := transport.NewHTTPTransport("https://hooks.example.com/reports")
tr.Client = &http.Client{Timeout: 10 * time.Second}
```

HTTPTransport returns an error for any non-2xx response.

---

## Custom transports

Implement the interface to send reports anywhere — S3, Slack, a database, etc.:

```go
type S3Transport struct {
    Bucket string
    Key    string
}

func (t *S3Transport) Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error {
    data, err := f.Format(r)
    if err != nil {
        return err
    }
    // upload data to S3...
    return nil
}
```

Then use it the same way:

```go
err := report.Send(ctx, &S3Transport{Bucket: "my-bucket", Key: "report.json"}, format.NewJSONFormatter())
```
