package format_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/internal/testdata"
)

func TestJSONLMediaTypeAndExtension(t *testing.T) {
	f := format.NewJSONLFormatter()
	if f.MediaType() != "application/x-ndjson" {
		t.Errorf("MediaType = %q", f.MediaType())
	}
	if f.FileExtension() != ".jsonl" {
		t.Errorf("FileExtension = %q", f.FileExtension())
	}
}

func TestJSONLLineCount(t *testing.T) {
	data, err := format.NewJSONLFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	lines := countNonEmptyLines(data)
	if lines != len(testdata.Fixtures()) {
		t.Errorf("line count = %d, want %d", lines, len(testdata.Fixtures()))
	}
}

func TestJSONLEachLineIsValidJSON(t *testing.T) {
	data, err := format.NewJSONLFormatter().Format(fullReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %v", lineNum, err)
		}
	}
}

func TestJSONLFindingFields(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{richFinding()},
	}
	data, err := format.NewJSONLFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var f map[string]any
	json.Unmarshal(bytes.TrimRight(data, "\n"), &f)

	if f["id"] != "rich-1" {
		t.Errorf("id = %v", f["id"])
	}
	if f["severity"] != "critical" {
		t.Errorf("severity = %v", f["severity"])
	}
	if f["cwe_id"] != "CWE-89" {
		t.Errorf("cwe_id = %v", f["cwe_id"])
	}
	if f["url"] != "https://api.example.com/users" {
		t.Errorf("url = %v", f["url"])
	}
}

func TestJSONLSchemaField(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, err := format.NewJSONLFormatter().Format(r)
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var f map[string]any
	json.Unmarshal(bytes.TrimRight(data, "\n"), &f)
	if f["$schema"] != format.FindingSchemaURL {
		t.Errorf("$schema = %v, want %v", f["$schema"], format.FindingSchemaURL)
	}
}

func TestJSONLEmptyReportProducesNoOutput(t *testing.T) {
	data, err := format.NewJSONLFormatter().Format(emptyReport())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Errorf("expected empty output, got %q", data)
	}
}

func TestJSONLLinesTerminateWithNewline(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewJSONLFormatter().Format(r)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("each JSONL line should end with a newline")
	}
}

func TestJSONLEvidenceOmittedWhenEmpty(t *testing.T) {
	r := &reportx.Report{
		ToolName: "T",
		ScanDate: time.Now(),
		Findings: []reportx.Finding{minimalFinding()},
	}
	data, _ := format.NewJSONLFormatter().Format(r)
	var f map[string]any
	json.Unmarshal(bytes.TrimRight(data, "\n"), &f)
	if _, ok := f["evidence"]; ok {
		t.Error("evidence should be omitted when empty")
	}
}

func countNonEmptyLines(data []byte) int {
	n := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) > 0 {
			n++
		}
	}
	return n
}
