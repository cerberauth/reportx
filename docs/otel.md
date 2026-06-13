# OpenTelemetry

reportx is instrumented with [OpenTelemetry](https://opentelemetry.io/). When a tracer provider is configured in the calling process, reportx emits spans automatically. No configuration is needed inside the library.

## Emitted spans

| Span name | Emitted by |
|-----------|------------|
| `reportx.Build` | `Builder.Build()` |
| `reportx.WriteTo` | `Report.WriteTo()` |
| `reportx.WriteToFile` | `Report.WriteToFile()` |
| `reportx.Send` | `Report.Send()` |
| `reportx.FSTransport.Send` | `transport.FSTransport.Send()` |
| `reportx.HTTPTransport.Send` | `transport.HTTPTransport.Send()` |

## Span attributes

### `reportx.Build`

| Attribute | Value |
|-----------|-------|
| `reportx.findings.count` | number of findings before enrichment/dedup |
| `reportx.tool.name` | tool name from `Builder.Tool()` |
| `reportx.target` | target from `Builder.Target()` |

### `reportx.WriteTo` / `reportx.WriteToFile`

| Attribute | Value |
|-----------|-------|
| `reportx.format` | formatter's `MediaType()` |
| `reportx.output.path` | file path (WriteToFile only) |

### `reportx.FSTransport.Send`

| Attribute | Value |
|-----------|-------|
| `reportx.output.dir` | destination directory |
| `reportx.output.filename` | output filename |

### `reportx.HTTPTransport.Send`

| Attribute | Value |
|-----------|-------|
| `http.request.method` | `POST` |
| `server.address` | destination URL |
| `http.response.status_code` | HTTP status of the response |

Errors are recorded on spans with `span.RecordError(err)` and the span status is set to `codes.Error`.

## Enabling tracing

reportx uses `otel.Tracer()` — it picks up whatever global provider is registered. Set up a provider once at process startup:

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
    "go.opentelemetry.io/otel/sdk/trace"
)

func initTracer(ctx context.Context) (func(context.Context) error, error) {
    exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
    if err != nil {
        return nil, err
    }
    tp := trace.NewTracerProvider(trace.WithBatcher(exp))
    otel.SetTracerProvider(tp)
    return tp.Shutdown, nil
}
```

No changes to reportx call sites are needed — pass the `context.Context` through as usual.

## Propagating context

All reportx methods accept `context.Context` as their first argument. Pass a context that carries an active span to nest reportx spans inside your own trace:

```go
ctx, span := tracer.Start(ctx, "my-scanner.scan")
defer span.End()

report, err := builder.Build(ctx)              // nested under my-scanner.scan
err = report.WriteTo(ctx, w, formatter)        // same trace
```

## Disabling telemetry

If no provider is registered (the default), all OTEL calls are no-ops. There is no performance overhead.
