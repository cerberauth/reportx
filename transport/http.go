package transport

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/cerberauth/reportx"
)

var tracer = otel.Tracer("github.com/cerberauth/reportx/transport")

// HTTPTransport POSTs a formatted report to a URL (webhook).
// The Content-Type header is set from the formatter's MediaType.
// Additional headers (e.g. Authorization) can be provided via Headers.
// If Client is nil, http.DefaultClient is used.
type HTTPTransport struct {
	URL     string
	Headers map[string]string
	Client  *http.Client
}

// NewHTTPTransport creates an HTTPTransport that POSTs to url.
func NewHTTPTransport(url string) *HTTPTransport {
	return &HTTPTransport{URL: url}
}

func (t *HTTPTransport) Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error {
	ctx, span := tracer.Start(ctx, "reportx.HTTPTransport.Send",
		trace.WithAttributes(
			attribute.String("http.request.method", http.MethodPost),
			attribute.String("server.address", t.URL),
		),
	)
	defer span.End()

	data, err := f.Format(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/http: format: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(data))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/http: build request: %w", err)
	}
	req.Header.Set("Content-Type", f.MediaType())
	req.Header.Set("X-Generated-By", reportx.Watermark)
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/http: do request: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("transport/http: unexpected status %d", resp.StatusCode)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}
