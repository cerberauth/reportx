package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/cerberauth/reportx"
)

// FSTransport writes a formatted report to the filesystem.
// If Filename is empty, it defaults to "report" + the formatter's file extension.
type FSTransport struct {
	Dir      string
	Filename string
}

// NewFSTransport creates an FSTransport that writes to dir.
func NewFSTransport(dir string) *FSTransport {
	return &FSTransport{Dir: dir}
}

func (t *FSTransport) Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error {
	filename := t.Filename
	if filename == "" {
		filename = "report" + f.FileExtension()
	}

	_, span := tracer.Start(ctx, "reportx.FSTransport.Send",
		trace.WithAttributes(
			attribute.String("reportx.output.dir", t.Dir),
			attribute.String("reportx.output.filename", filename),
		),
	)
	defer span.End()

	data, err := f.Format(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/fs: format: %w", err)
	}

	if err := os.MkdirAll(t.Dir, 0o755); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/fs: mkdir: %w", err)
	}

	path := filepath.Join(t.Dir, filename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("transport/fs: write: %w", err)
	}
	return nil
}
