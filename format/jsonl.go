package format

import (
	"bytes"
	"encoding/json"

	"github.com/cerberauth/reportx"
)

type JSONLFormatter struct{}

// jsonlScanSummary is the optional trailing line of JSONL output, emitted only
// when the report carries scan errors or coverage. Finding lines have no
// "type" key, so consumers can tell the two apart.
type jsonlScanSummary struct {
	Type     string          `json:"type"`
	Errors   []jsonScanError `json:"errors,omitempty"`
	Coverage *jsonCoverage   `json:"coverage,omitempty"`
}

func NewJSONLFormatter() *JSONLFormatter { return &JSONLFormatter{} }

func (f *JSONLFormatter) Format(r *reportx.Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, finding := range r.Findings {
		jf := toJSONFinding(finding)
		jf.Schema = FindingSchemaURL
		if err := enc.Encode(jf); err != nil {
			return nil, err
		}
	}
	if len(r.Errors) > 0 || !r.Coverage.IsZero() {
		line := jsonlScanSummary{
			Type:     "scan_summary",
			Errors:   toJSONErrors(r.Errors),
			Coverage: toJSONCoverage(r.Coverage),
		}
		if err := enc.Encode(line); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (f *JSONLFormatter) MediaType() string     { return "application/x-ndjson" }
func (f *JSONLFormatter) FileExtension() string { return ".jsonl" }
