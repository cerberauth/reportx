package format

import (
	"encoding/json"
	"time"

	"github.com/cerberauth/reportx"
)

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter { return &JSONFormatter{} }

type jsonEvidence struct {
	RawRequest      string              `json:"raw_request,omitempty"`
	RawResponse     string              `json:"raw_response,omitempty"`
	RequestMethod   string              `json:"request_method,omitempty"`
	RequestURL      string              `json:"request_url,omitempty"`
	ResponseStatus  int                 `json:"response_status,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	RequestBody     string              `json:"request_body,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
}

type jsonFinding struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Severity        reportx.Severity  `json:"severity"`
	CVSS31Score     float64           `json:"cvss31_score,omitempty"`
	CVSS31Vector    string            `json:"cvss31_vector,omitempty"`
	CVSS40Score     float64           `json:"cvss40_score,omitempty"`
	CVSS40Vector    string            `json:"cvss40_vector,omitempty"`
	CWEID           string            `json:"cwe_id,omitempty"`
	CWEName         string            `json:"cwe_name,omitempty"`
	OwaspTop10      string            `json:"owasp_top10,omitempty"`
	URL             string            `json:"url,omitempty"`
	Parameter       string            `json:"parameter,omitempty"`
	Evidence        *jsonEvidence     `json:"evidence,omitempty"`
	Description     string            `json:"description,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	FirstSeen       string            `json:"first_seen,omitempty"`
	LastSeen        string            `json:"last_seen,omitempty"`
	Status          reportx.Status    `json:"status"`
	FingerprintHash string            `json:"fingerprint_hash,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	Extra           map[string]string `json:"extra,omitempty"`
}

type jsonMetadata struct {
	Title       string                   `json:"title"`
	Tool        string                   `json:"tool"`
	Version     string                   `json:"version"`
	ScanDate    string                   `json:"scan_date"`
	Target      string                   `json:"target"`
	Total       int                      `json:"total"`
	BySeverity  map[reportx.Severity]int `json:"by_severity"`
	GeneratedBy string                   `json:"generated_by"`
}

type jsonReport struct {
	Metadata jsonMetadata  `json:"metadata"`
	Findings []jsonFinding `json:"findings"`
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
	if !f.Evidence.IsEmpty() {
		e := f.Evidence
		jf.Evidence = &jsonEvidence{
			RawRequest:      e.RawRequest,
			RawResponse:     e.RawResponse,
			RequestMethod:   e.RequestMethod,
			RequestURL:      e.RequestURL,
			ResponseStatus:  e.ResponseStatus,
			ResponseHeaders: e.ResponseHeaders,
			RequestBody:     string(e.RequestBody),
			ResponseBody:    string(e.ResponseBody),
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
