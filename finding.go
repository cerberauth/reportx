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

type Evidence interface {
	IsEmpty() bool
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
	CAPECID         string
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
