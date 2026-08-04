package format

import (
	"time"

	"github.com/cerberauth/reportx"
	"gopkg.in/yaml.v3"
)

type YAMLFormatter struct{}

func NewYAMLFormatter() *YAMLFormatter { return &YAMLFormatter{} }

func (f *YAMLFormatter) Format(r *reportx.Report) ([]byte, error) {
	findings := make([]jsonFinding, len(r.Findings))
	for i, finding := range r.Findings {
		findings[i] = toJSONFinding(finding)
	}

	out := jsonReport{
		Metadata: jsonMetadata{
			Title:       r.Title,
			Tool:        r.ToolName,
			Version:     r.ToolVersion,
			ScanDate:    r.ScanDate.Format(time.RFC3339),
			Target:      r.Target,
			Total:       len(r.Findings),
			BySeverity:  r.SeverityCounts(),
			GeneratedBy: reportx.Watermark,
		},
		Findings: findings,
	}
	return yaml.Marshal(out)
}

func (f *YAMLFormatter) MediaType() string     { return "application/yaml" }
func (f *YAMLFormatter) FileExtension() string { return ".yaml" }
