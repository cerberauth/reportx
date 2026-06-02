package score

import "github.com/cerberauth/reportx"

func Label(score float64) reportx.Severity {
	switch {
	case score >= 9.0:
		return reportx.SeverityCritical
	case score >= 7.0:
		return reportx.SeverityHigh
	case score >= 4.0:
		return reportx.SeverityMedium
	case score > 0.0:
		return reportx.SeverityLow
	default:
		return reportx.SeverityInfo
	}
}
