package reportx

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Status string

const (
	StatusActive        Status = "active"
	StatusFalsePositive Status = "false_positive"
	StatusAcceptedRisk  Status = "accepted_risk"
	StatusMitigated     Status = "mitigated"
)

type Evidence struct {
	RawRequest      string
	RawResponse     string
	RequestMethod   string
	RequestURL      string
	ResponseStatus  int
	ResponseHeaders map[string][]string
	RequestBody     []byte
	ResponseBody    []byte
}

func (e Evidence) HasStructured() bool {
	return e.RequestMethod != "" || e.RequestURL != "" || e.ResponseStatus != 0 ||
		len(e.ResponseHeaders) > 0 || len(e.RequestBody) > 0 || len(e.ResponseBody) > 0
}

func (e Evidence) IsEmpty() bool {
	return e.RawRequest == "" && e.RawResponse == "" && !e.HasStructured()
}

type Finding struct {
	ID              string
	Title           string
	Severity        Severity
	CVSS31Score     float64
	CVSS31Vector    string
	CVSS40Score     float64
	CVSS40Vector    string
	CWEID           string
	CWEName         string
	OwaspTop10      string
	URL             string
	Parameter       string
	Evidence        Evidence
	Description     string
	Remediation     string
	FirstSeen       time.Time
	LastSeen        time.Time
	Status          Status
	FingerprintHash string
	Tags            []string
	Extra           map[string]string
}
