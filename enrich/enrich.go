package enrich

import (
	"github.com/cerberauth/reportx"
)

type Enricher interface {
	Enrich(f *reportx.Finding) error
}

type DefaultEnricher struct{}

func NewDefaultEnricher() *DefaultEnricher {
	initCWEMap()
	return &DefaultEnricher{}
}

func (e *DefaultEnricher) Enrich(f *reportx.Finding) error {
	if f.CWEID == "" {
		return nil
	}
	record, ok := Lookup(f.CWEID)
	if !ok {
		return nil
	}
	if f.CWEName == "" {
		f.CWEName = record.ShortName
		if f.CWEName == "" {
			f.CWEName = record.Name
		}
	}
	if f.OwaspTop10 == "" && record.OWASP2021 != "" {
		f.OwaspTop10 = record.OWASP2021
	}
	return nil
}

func EnrichAll(findings []reportx.Finding) []reportx.Finding {
	e := NewDefaultEnricher()
	out := make([]reportx.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		_ = e.Enrich(&out[i])
	}
	return out
}
