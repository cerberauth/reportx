package reportx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("github.com/cerberauth/reportx")

type Report struct {
	Title       string
	ScanDate    time.Time
	ToolName    string
	ToolVersion string
	Target      string
	Findings    []Finding
}

func (r *Report) SeverityCounts() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

func (r *Report) FindingsByStatus(s Status) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == s {
			out = append(out, f)
		}
	}
	return out
}

func (r *Report) FindingsBySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

type Formatter interface {
	Format(r *Report) ([]byte, error)
	MediaType() string
	FileExtension() string
}

func (r *Report) WriteTo(ctx context.Context, w io.Writer, f Formatter) error {
	_, span := tracer.Start(ctx, "reportx.WriteTo",
		trace.WithAttributes(attribute.String("reportx.format", f.MediaType())),
	)
	defer span.End()

	data, err := f.Format(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("reportx: format failed: %w", err)
	}
	if _, err = w.Write(data); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

func (r *Report) WriteToFile(ctx context.Context, path string, f Formatter) error {
	_, span := tracer.Start(ctx, "reportx.WriteToFile",
		trace.WithAttributes(
			attribute.String("reportx.format", f.MediaType()),
			attribute.String("reportx.output.path", path),
		),
	)
	defer span.End()

	data, err := f.Format(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("reportx: format failed: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("reportx: create file: %w", err)
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

type Transport interface {
	Send(ctx context.Context, r *Report, f Formatter) error
}

func (r *Report) Send(ctx context.Context, t Transport, f Formatter) error {
	ctx, span := tracer.Start(ctx, "reportx.Send")
	defer span.End()

	if err := t.Send(ctx, r, f); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Sink pairs a Formatter with exactly one delivery target for a report:
// either a Writer (stdout, a file, ...) or a Transport (HTTP, ...).
type Sink struct {
	Formatter Formatter
	Writer    io.Writer // mutually exclusive with Transport
	Transport Transport // mutually exclusive with Writer
}

func (s Sink) deliver(ctx context.Context, r *Report) error {
	if s.Transport != nil {
		return r.Send(ctx, s.Transport, s.Formatter)
	}
	return r.WriteTo(ctx, s.Writer, s.Formatter)
}

// DeliverAll delivers the report to every sink, each in its own format, so
// e.g. a terminal display, a JSON file, and an HTTP POST in another format
// can all happen from a single report. Errors from individual sinks are
// joined rather than short-circuiting delivery to the rest.
func (r *Report) DeliverAll(ctx context.Context, sinks []Sink) error {
	var errs []error
	for _, s := range sinks {
		if err := s.deliver(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type EnrichFunc func([]Finding) []Finding

type DedupFunc func([]Finding) []Finding

type Builder struct {
	title       string
	scanDate    time.Time
	toolName    string
	toolVersion string
	target      string
	findings    []Finding
	enrichFunc  EnrichFunc
	dedupFunc   DedupFunc
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Title(title string) *Builder {
	b.title = title
	return b
}

func (b *Builder) Tool(name, version string) *Builder {
	b.toolName = name
	b.toolVersion = version
	return b
}

func (b *Builder) Target(target string) *Builder {
	b.target = target
	return b
}

func (b *Builder) ScanDate(t time.Time) *Builder {
	b.scanDate = t
	return b
}

func (b *Builder) Findings(findings []Finding) *Builder {
	b.findings = findings
	return b
}

func (b *Builder) Enrich(fn EnrichFunc) *Builder {
	b.enrichFunc = fn
	return b
}

func (b *Builder) Deduplicate(fn DedupFunc) *Builder {
	b.dedupFunc = fn
	return b
}

func (b *Builder) Build(ctx context.Context) (*Report, error) {
	_, span := tracer.Start(ctx, "reportx.Build",
		trace.WithAttributes(
			attribute.Int("reportx.findings.count", len(b.findings)),
			attribute.String("reportx.tool.name", b.toolName),
			attribute.String("reportx.target", b.target),
		),
	)
	defer span.End()

	findings := make([]Finding, len(b.findings))
	copy(findings, b.findings)

	if b.enrichFunc != nil {
		findings = b.enrichFunc(findings)
	}

	if b.dedupFunc != nil {
		findings = b.dedupFunc(findings)
	}

	scanDate := b.scanDate
	if scanDate.IsZero() {
		scanDate = time.Now()
	}

	return &Report{
		Title:       b.title,
		ScanDate:    scanDate,
		ToolName:    b.toolName,
		ToolVersion: b.toolVersion,
		Target:      b.target,
		Findings:    findings,
	}, nil
}
