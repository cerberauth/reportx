package score_test

import (
	"math"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/score"
)

func TestCalculateV31(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := score.CalculateV31(tt.vector)
			if err != nil {
				t.Fatalf("CalculateV31(%q) error: %v", tt.vector, err)
			}
			if math.Abs(got-tt.want) > 0.1 {
				t.Errorf("CalculateV31(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
			}
		})
	}
}

func TestCalculateV31Errors(t *testing.T) {
	bad := []string{
		"",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
		"notavector",
	}
	for _, v := range bad {
		_, err := score.CalculateV31(v)
		if err == nil {
			t.Errorf("CalculateV31(%q) should return error", v)
		}
	}
}

func TestCalculateV40(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.3},
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.0},
		{"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 8.6},
		{"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.2},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 6.9},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := score.CalculateV40(tt.vector)
			if err != nil {
				t.Fatalf("CalculateV40(%q) error: %v", tt.vector, err)
			}
			if math.Abs(got-tt.want) > 0.1 {
				t.Errorf("CalculateV40(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
			}
		})
	}
}

func TestCalculateV40Errors(t *testing.T) {
	bad := []string{
		"",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H",
		"CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		"notavector",
	}
	for _, v := range bad {
		_, err := score.CalculateV40(v)
		if err == nil {
			t.Errorf("CalculateV40(%q) should return error", v)
		}
	}
}

func TestLabel(t *testing.T) {
	tests := []struct {
		score float64
		want  reportx.Severity
	}{
		{10.0, reportx.SeverityCritical},
		{9.0, reportx.SeverityCritical},
		{8.9, reportx.SeverityHigh},
		{7.0, reportx.SeverityHigh},
		{6.9, reportx.SeverityMedium},
		{4.0, reportx.SeverityMedium},
		{3.9, reportx.SeverityLow},
		{0.1, reportx.SeverityLow},
		{0.0, reportx.SeverityInfo},
	}
	for _, tt := range tests {
		got := score.Label(tt.score)
		if got != tt.want {
			t.Errorf("Label(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
