package format

import (
	"bytes"
	"encoding/json"

	"github.com/cerberauth/reportx"
)

type JSONLFormatter struct{}

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
	return buf.Bytes(), nil
}

func (f *JSONLFormatter) MediaType() string     { return "application/x-ndjson" }
func (f *JSONLFormatter) FileExtension() string { return ".jsonl" }
