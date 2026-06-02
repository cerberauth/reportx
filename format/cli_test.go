package format_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/reportx/format"
)

func TestNewFormatterAllNames(t *testing.T) {
	cases := []struct {
		name      string
		wantMedia string
		wantExt   string
	}{
		{"json", "application/json", ".json"},
		{"jsonl", "application/x-ndjson", ".jsonl"},
		{"sarif", "application/sarif+json", ".sarif.json"},
		{"markdown", "text/markdown", ".md"},
		{"md", "text/markdown", ".md"},
		{"html", "text/html", ".html"},
		{"terminal", "text/plain", ".txt"},
		{"text", "text/plain", ".txt"},
		{"plain", "text/plain", ".txt"},
	}
	for _, tc := range cases {
		f, err := format.NewFormatter(tc.name)
		if err != nil {
			t.Errorf("NewFormatter(%q) unexpected error: %v", tc.name, err)
			continue
		}
		if f.MediaType() != tc.wantMedia {
			t.Errorf("NewFormatter(%q).MediaType() = %q, want %q", tc.name, f.MediaType(), tc.wantMedia)
		}
		if f.FileExtension() != tc.wantExt {
			t.Errorf("NewFormatter(%q).FileExtension() = %q, want %q", tc.name, f.FileExtension(), tc.wantExt)
		}
	}
}

func TestNewFormatterUnknownReturnsError(t *testing.T) {
	for _, name := range []string{"unknown", "", "XML", "pdf"} {
		if _, err := format.NewFormatter(name); err == nil {
			t.Errorf("NewFormatter(%q) should return an error", name)
		}
	}
}

func TestNewFormatterErrorMessageContainsValidNames(t *testing.T) {
	_, err := format.NewFormatter("bad")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, name := range []string{"json", "jsonl", "sarif", "markdown", "html", "terminal"} {
		if !containsStr(msg, name) {
			t.Errorf("error message should mention %q, got: %s", name, msg)
		}
	}
}

func TestRegisterFlagsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := format.RegisterFlags(fs)
	fs.Parse([]string{})

	if flags.Format != "terminal" {
		t.Errorf("default Format = %q, want terminal", flags.Format)
	}
	if flags.Output != "" {
		t.Errorf("default Output = %q, want empty", flags.Output)
	}
	if flags.NoColor != false {
		t.Errorf("default NoColor = %v, want false", flags.NoColor)
	}
}

func TestRegisterFlagsParsed(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := format.RegisterFlags(fs)
	fs.Parse([]string{"--format", "json", "--output", "/tmp/report.json", "--no-color"})

	if flags.Format != "json" {
		t.Errorf("Format = %q, want json", flags.Format)
	}
	if flags.Output != "/tmp/report.json" {
		t.Errorf("Output = %q, want /tmp/report.json", flags.Output)
	}
	if !flags.NoColor {
		t.Error("NoColor should be true")
	}
}

func TestCLIFlagsFormatterReturnsCorrectType(t *testing.T) {
	cases := []struct {
		format    string
		wantMedia string
	}{
		{"json", "application/json"},
		{"sarif", "application/sarif+json"},
		{"markdown", "text/markdown"},
		{"html", "text/html"},
		{"terminal", "text/plain"},
	}
	for _, tc := range cases {
		flags := &format.CLIFlags{Format: tc.format}
		f, err := flags.Formatter()
		if err != nil {
			t.Errorf("Formatter() for %q error: %v", tc.format, err)
			continue
		}
		if f.MediaType() != tc.wantMedia {
			t.Errorf("Formatter() for %q: MediaType = %q, want %q", tc.format, f.MediaType(), tc.wantMedia)
		}
	}
}

func TestCLIFlagsFormatterNoColorTerminal(t *testing.T) {
	flags := &format.CLIFlags{Format: "terminal", NoColor: true}
	f, err := flags.Formatter()
	if err != nil {
		t.Fatalf("Formatter() error: %v", err)
	}
	r := fullReport()
	data, err := f.Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	if containsStr(string(data), "\033[") {
		t.Error("NoColor formatter should produce no ANSI escape codes")
	}
}

func TestCLIFlagsFormatterNoColorAliases(t *testing.T) {
	for _, name := range []string{"text", "plain"} {
		flags := &format.CLIFlags{Format: name, NoColor: true}
		f, err := flags.Formatter()
		if err != nil {
			t.Errorf("Formatter() for %q error: %v", name, err)
			continue
		}
		data, _ := f.Format(fullReport())
		if containsStr(string(data), "\033[") {
			t.Errorf("NoColor %q formatter should not produce ANSI codes", name)
		}
	}
}

func TestCLIFlagsFormatterUnknownReturnsError(t *testing.T) {
	flags := &format.CLIFlags{Format: "xml"}
	if _, err := flags.Formatter(); err == nil {
		t.Error("Formatter() with unknown format should return an error")
	}
}

func TestCLIFlagsWriterStdout(t *testing.T) {
	flags := &format.CLIFlags{Output: ""}
	w, close, err := flags.Writer()
	if err != nil {
		t.Fatalf("Writer() error: %v", err)
	}
	defer close()
	if w != os.Stdout {
		t.Error("Writer() with empty Output should return os.Stdout")
	}
}

func TestCLIFlagsWriterFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "report.json")
	flags := &format.CLIFlags{Output: tmp}
	w, close, err := flags.Writer()
	if err != nil {
		t.Fatalf("Writer() error: %v", err)
	}
	defer close()

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	close()

	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("file content = %q, want hello", got)
	}
}

func TestCLIFlagsWriterErrorOnBadPath(t *testing.T) {
	flags := &format.CLIFlags{Output: "/nonexistent/path/report.json"}
	if _, _, err := flags.Writer(); err == nil {
		t.Error("Writer() should return an error for an unwritable path")
	}
}

func TestFormatNamesContainsAllFormats(t *testing.T) {
	expected := map[format.FormatName]bool{
		format.FormatJSON:     false,
		format.FormatJSONL:    false,
		format.FormatSARIF:    false,
		format.FormatMarkdown: false,
		format.FormatHTML:     false,
		format.FormatTerminal: false,
	}
	for _, name := range format.FormatNames {
		expected[name] = true
	}
	for name, found := range expected {
		if !found {
			t.Errorf("FormatNames is missing %q", name)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
