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

// Confidence says how sure the producer is that a finding is real. The empty
// value means unspecified, for producers that do not report it.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceFirm      Confidence = "firm"
	ConfidenceTentative Confidence = "tentative"
)

// rank orders levels from least (1) to most (3) certain; 0 is unspecified or unknown.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceTentative:
		return 1
	case ConfidenceFirm:
		return 2
	case ConfidenceConfirmed:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether c is as certain as min. An unspecified c always
// passes, so findings from producers that do not set confidence are never
// dropped by a confidence filter; an unspecified min matches everything.
func (c Confidence) AtLeast(min Confidence) bool {
	if c.rank() == 0 || min.rank() == 0 {
		return true
	}
	return c.rank() >= min.rank()
}

type Evidence interface {
	IsEmpty() bool
}

// Finding is a single security issue. URL is the affected endpoint; advisory and
// documentation links belong in References (References[0] is the SARIF rule helpUri).
// Confidence is optional and does not take part in the fingerprint, so a finding keeps
// its identity when its confidence changes.
type Finding struct {
	ID              string
	Title           string
	Severity        Severity
	Confidence      Confidence
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
	References      []string
	FirstSeen       time.Time
	LastSeen        time.Time
	Status          Status
	FingerprintHash string
	Tags            []string
	Extra           map[string]string
}
