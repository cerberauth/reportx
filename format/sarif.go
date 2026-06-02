package format

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cerberauth/reportx"
)

type SARIFFormatter struct{}

func NewSARIFFormatter() *SARIFFormatter { return &SARIFFormatter{} }

type sarifRoot struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func sarifLevel(s reportx.Severity) string {
	switch s {
	case reportx.SeverityCritical, reportx.SeverityHigh:
		return "error"
	case reportx.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (f *SARIFFormatter) Format(r *reportx.Report) ([]byte, error) {
	ruleMap := make(map[string]sarifRule)
	ruleOrder := []string{}
	for _, finding := range r.Findings {
		ruleID := finding.CWEID
		if ruleID == "" {
			ruleID = "UNKNOWN"
		}
		if _, exists := ruleMap[ruleID]; !exists {
			name := finding.CWEName
			if name == "" {
				name = ruleID
			}
			props := map[string]any{
				"tags": []string{"security"},
			}
			if finding.OwaspTop10 != "" {
				props["tags"] = []string{"security", finding.OwaspTop10}
			}
			if finding.CVSS40Score > 0 {
				props["security-severity"] = fmt.Sprintf("%.1f", finding.CVSS40Score)
			} else if finding.CVSS31Score > 0 {
				props["security-severity"] = fmt.Sprintf("%.1f", finding.CVSS31Score)
			}
			ruleMap[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             name,
				ShortDescription: sarifMessage{Text: name},
				Properties:       props,
			}
			ruleOrder = append(ruleOrder, ruleID)
		}
	}
	sort.Strings(ruleOrder)
	rules := make([]sarifRule, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, ruleMap[id])
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, finding := range r.Findings {
		ruleID := finding.CWEID
		if ruleID == "" {
			ruleID = "UNKNOWN"
		}
		result := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Description},
		}
		if finding.URL != "" {
			result.Locations = []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: finding.URL},
				}},
			}
		}
		if finding.FingerprintHash != "" {
			result.PartialFingerprints = map[string]string{
				"primaryLocationLineHash": finding.FingerprintHash,
			}
		}
		props := map[string]any{}
		if finding.CVSS40Score > 0 {
			props["security-severity"] = fmt.Sprintf("%.1f", finding.CVSS40Score)
		} else if finding.CVSS31Score > 0 {
			props["security-severity"] = fmt.Sprintf("%.1f", finding.CVSS31Score)
		}
		if len(props) > 0 {
			result.Properties = props
		}
		results = append(results, result)
	}

	root := sarifRoot{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           r.ToolName,
						Version:        r.ToolVersion,
						InformationURI: "https://github.com/cerberauth/reportx",
						Rules:          rules,
					},
				},
				Results: results,
				Properties: map[string]any{
					"generated_by": reportx.Watermark,
				},
			},
		},
	}
	return json.MarshalIndent(root, "", "  ")
}

func (f *SARIFFormatter) MediaType() string     { return "application/sarif+json" }
func (f *SARIFFormatter) FileExtension() string { return ".sarif.json" }
