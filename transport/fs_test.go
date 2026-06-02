package transport_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/transport"
)

func TestFSTransport_DefaultFilename(t *testing.T) {
	dir := t.TempDir()
	tr := transport.NewFSTransport(dir)
	f := format.NewJSONFormatter()

	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}
	if err := tr.Send(context.Background(), report, f); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	path := filepath.Join(dir, "report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("output file not found: %v", err)
	}
	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestFSTransport_CustomFilename(t *testing.T) {
	dir := t.TempDir()
	tr := &transport.FSTransport{Dir: dir, Filename: "my-report.json"}
	f := format.NewJSONFormatter()

	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}
	if err := tr.Send(context.Background(), report, f); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "my-report.json")); err != nil {
		t.Errorf("expected my-report.json: %v", err)
	}
}

func TestFSTransport_CreatesDirIfMissing(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "reports")
	tr := transport.NewFSTransport(dir)
	f := format.NewJSONFormatter()

	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}
	if err := tr.Send(context.Background(), report, f); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Errorf("expected output file: %v", err)
	}
}
