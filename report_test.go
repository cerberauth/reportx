package reportx_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cerberauth/reportx"
)

type fakeFormatter struct {
	out []byte
	err error
}

func (f fakeFormatter) Format(r *reportx.Report) ([]byte, error) { return f.out, f.err }
func (f fakeFormatter) MediaType() string                        { return "text/plain" }
func (f fakeFormatter) FileExtension() string                    { return ".txt" }

type fakeTransport struct {
	sent []byte
	err  error
}

func (t *fakeTransport) Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error {
	if t.err != nil {
		return t.err
	}
	data, err := f.Format(r)
	if err != nil {
		return err
	}
	t.sent = data
	return nil
}

func TestSinkDeliverAllWriter(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	var buf bytes.Buffer
	sink := reportx.Sink{Formatter: fakeFormatter{out: []byte("report-data")}, Writer: &buf}

	if err := report.DeliverAll(context.Background(), []reportx.Sink{sink}); err != nil {
		t.Fatalf("DeliverAll() error: %v", err)
	}
	if buf.String() != "report-data" {
		t.Errorf("buf = %q, want %q", buf.String(), "report-data")
	}
}

func TestSinkDeliverAllTransport(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	transport := &fakeTransport{}
	sink := reportx.Sink{Formatter: fakeFormatter{out: []byte("report-data")}, Transport: transport}

	if err := report.DeliverAll(context.Background(), []reportx.Sink{sink}); err != nil {
		t.Fatalf("DeliverAll() error: %v", err)
	}
	if string(transport.sent) != "report-data" {
		t.Errorf("transport.sent = %q, want %q", transport.sent, "report-data")
	}
}

func TestSinkDeliverAllMultipleSinks(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	var buf bytes.Buffer
	transport := &fakeTransport{}
	sinks := []reportx.Sink{
		{Formatter: fakeFormatter{out: []byte("to-writer")}, Writer: &buf},
		{Formatter: fakeFormatter{out: []byte("to-transport")}, Transport: transport},
	}

	if err := report.DeliverAll(context.Background(), sinks); err != nil {
		t.Fatalf("DeliverAll() error: %v", err)
	}
	if buf.String() != "to-writer" {
		t.Errorf("buf = %q, want %q", buf.String(), "to-writer")
	}
	if string(transport.sent) != "to-transport" {
		t.Errorf("transport.sent = %q, want %q", transport.sent, "to-transport")
	}
}

func TestSinkDeliverAllCollectsErrors(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	writerErr := errors.New("format failed")
	transportErr := errors.New("send failed")
	sinks := []reportx.Sink{
		{Formatter: fakeFormatter{err: writerErr}, Writer: &bytes.Buffer{}},
		{Formatter: fakeFormatter{out: []byte("data")}, Transport: &fakeTransport{err: transportErr}},
	}

	err := report.DeliverAll(context.Background(), sinks)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, writerErr) {
		t.Errorf("expected joined error to include %v", writerErr)
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("expected joined error to include %v", transportErr)
	}
}

func TestSinkDeliverAllNoSinks(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	if err := report.DeliverAll(context.Background(), nil); err != nil {
		t.Fatalf("DeliverAll() with no sinks error: %v", err)
	}
}

func TestReportWriteTo(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	var buf bytes.Buffer
	if err := report.WriteTo(context.Background(), &buf, fakeFormatter{out: []byte("data")}); err != nil {
		t.Fatalf("WriteTo() error: %v", err)
	}
	if buf.String() != "data" {
		t.Errorf("buf = %q, want %q", buf.String(), "data")
	}
}

func TestReportWriteToFormatError(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	wantErr := errors.New("format failed")
	var buf bytes.Buffer
	err := report.WriteTo(context.Background(), &buf, fakeFormatter{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Errorf("WriteTo() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestReportSend(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	transport := &fakeTransport{}
	if err := report.Send(context.Background(), transport, fakeFormatter{out: []byte("data")}); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if string(transport.sent) != "data" {
		t.Errorf("transport.sent = %q, want %q", transport.sent, "data")
	}
}

func TestReportSendError(t *testing.T) {
	report := &reportx.Report{Title: "Test"}
	wantErr := errors.New("send failed")
	transport := &fakeTransport{err: wantErr}
	err := report.Send(context.Background(), transport, fakeFormatter{out: []byte("data")})
	if !errors.Is(err, wantErr) {
		t.Errorf("Send() error = %v, want %v", err, wantErr)
	}
}
