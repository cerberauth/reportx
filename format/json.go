package format

import (
	"encoding/json"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
)

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter { return &JSONFormatter{} }

// ReportSchemaURL and FindingSchemaURL point at the JSON Schemas published
// for reportx's JSON and JSONL output on schemas.cerberauth.com.
const (
	ReportSchemaURL  = "https://schemas.cerberauth.com/reportx/v0.3.0/report.schema.json"
	FindingSchemaURL = "https://schemas.cerberauth.com/reportx/v0.3.0/finding.schema.json"
)

type jsonEvidence struct {
	RawRequest      string              `json:"raw_request,omitempty" yaml:"raw_request,omitempty"`
	RawResponse     string              `json:"raw_response,omitempty" yaml:"raw_response,omitempty"`
	RequestMethod   string              `json:"request_method,omitempty" yaml:"request_method,omitempty"`
	RequestURL      string              `json:"request_url,omitempty" yaml:"request_url,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers,omitempty" yaml:"request_headers,omitempty"`
	ResponseStatus  int                 `json:"response_status,omitempty" yaml:"response_status,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty" yaml:"response_headers,omitempty"`
	RequestBody     string              `json:"request_body,omitempty" yaml:"request_body,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty" yaml:"response_body,omitempty"`
}

type jsonFinding struct {
	Schema          string            `json:"$schema,omitempty" yaml:"$schema,omitempty"`
	ID              string            `json:"id" yaml:"id"`
	Title           string            `json:"title" yaml:"title"`
	Severity        reportx.Severity  `json:"severity" yaml:"severity"`
	CVSS31Score     float64           `json:"cvss31_score,omitempty" yaml:"cvss31_score,omitempty"`
	CVSS31Vector    string            `json:"cvss31_vector,omitempty" yaml:"cvss31_vector,omitempty"`
	CVSS40Score     float64           `json:"cvss40_score,omitempty" yaml:"cvss40_score,omitempty"`
	CVSS40Vector    string            `json:"cvss40_vector,omitempty" yaml:"cvss40_vector,omitempty"`
	CWEID           string            `json:"cwe_id,omitempty" yaml:"cwe_id,omitempty"`
	CWEName         string            `json:"cwe_name,omitempty" yaml:"cwe_name,omitempty"`
	OwaspTop10      string            `json:"owasp_top10,omitempty" yaml:"owasp_top10,omitempty"`
	CAPECID         string            `json:"capec_id,omitempty" yaml:"capec_id,omitempty"`
	URL             string            `json:"url,omitempty" yaml:"url,omitempty"`
	Parameter       string            `json:"parameter,omitempty" yaml:"parameter,omitempty"`
	Evidence        any               `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Description     string            `json:"description,omitempty" yaml:"description,omitempty"`
	Remediation     string            `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	FirstSeen       string            `json:"first_seen,omitempty" yaml:"first_seen,omitempty"`
	LastSeen        string            `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	Status          reportx.Status    `json:"status" yaml:"status"`
	FingerprintHash string            `json:"fingerprint_hash,omitempty" yaml:"fingerprint_hash,omitempty"`
	Tags            []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Extra           map[string]string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

type jsonMetadata struct {
	Title       string                   `json:"title" yaml:"title"`
	Tool        string                   `json:"tool" yaml:"tool"`
	Version     string                   `json:"version" yaml:"version"`
	ScanDate    string                   `json:"scan_date" yaml:"scan_date"`
	Target      string                   `json:"target" yaml:"target"`
	Total       int                      `json:"total" yaml:"total"`
	BySeverity  map[reportx.Severity]int `json:"by_severity" yaml:"by_severity"`
	GeneratedBy string                   `json:"generated_by" yaml:"generated_by"`
}

type jsonReport struct {
	Schema   string        `json:"$schema,omitempty" yaml:"$schema,omitempty"`
	Metadata jsonMetadata  `json:"metadata" yaml:"metadata"`
	Findings []jsonFinding `json:"findings" yaml:"findings"`
}

func toJSONFinding(f reportx.Finding) jsonFinding {
	jf := jsonFinding{
		ID:              f.ID,
		Title:           f.Title,
		Severity:        f.Severity,
		CVSS31Score:     f.CVSS31Score,
		CVSS31Vector:    f.CVSS31Vector,
		CVSS40Score:     f.CVSS40Score,
		CVSS40Vector:    f.CVSS40Vector,
		CWEID:           f.CWEID,
		CWEName:         f.CWEName,
		OwaspTop10:      f.OwaspTop10,
		CAPECID:         f.CAPECID,
		URL:             f.URL,
		Parameter:       f.Parameter,
		Description:     f.Description,
		Remediation:     f.Remediation,
		Status:          f.Status,
		FingerprintHash: f.FingerprintHash,
		Tags:            f.Tags,
		Extra:           f.Extra,
	}
	if !f.FirstSeen.IsZero() {
		jf.FirstSeen = f.FirstSeen.Format(time.RFC3339)
	}
	if !f.LastSeen.IsZero() {
		jf.LastSeen = f.LastSeen.Format(time.RFC3339)
	}
	switch ev := f.Evidence.(type) {
	case *evidence.HTTPEvidence:
		if !ev.IsEmpty() {
			jf.Evidence = &jsonEvidence{
				RawRequest:      ev.RawRequest,
				RawResponse:     ev.RawResponse,
				RequestMethod:   ev.RequestMethod,
				RequestURL:      ev.RequestURL,
				RequestHeaders:  ev.RequestHeaders,
				ResponseStatus:  ev.ResponseStatus,
				ResponseHeaders: ev.ResponseHeaders,
				RequestBody:     string(ev.RequestBody),
				ResponseBody:    string(ev.ResponseBody),
			}
		}
	case *evidence.CustomEvidence:
		if !ev.IsEmpty() {
			jf.Evidence = ev.Data
		}
	}
	return jf
}

func (f *JSONFormatter) Format(r *reportx.Report) ([]byte, error) {
	findings := make([]jsonFinding, len(r.Findings))
	for i, finding := range r.Findings {
		findings[i] = toJSONFinding(finding)
	}

	out := jsonReport{
		Schema: ReportSchemaURL,
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
	return json.MarshalIndent(out, "", "  ")
}

func (f *JSONFormatter) MediaType() string     { return "application/json" }
func (f *JSONFormatter) FileExtension() string { return ".json" }
