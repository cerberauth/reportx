package enrich

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed data/cwe.json
var cweData []byte

type CWERecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ShortName string `json:"short_name"`
	OWASP2021 string `json:"owasp_2021"`
	OWASP2025 string `json:"owasp_2025"`
}

var (
	cweOnce  sync.Once
	cweMap   map[string]*CWERecord
	cweError error
)

func initCWEMap() {
	cweOnce.Do(func() {
		var records []CWERecord
		if err := json.Unmarshal(cweData, &records); err != nil {
			cweError = err
			return
		}
		cweMap = make(map[string]*CWERecord, len(records))
		for i := range records {
			r := &records[i]
			normalized := normalizeID(r.ID)
			cweMap[normalized] = r
		}
	})
}

func normalizeID(id string) string {
	id = strings.TrimSpace(id)
	upper := strings.ToUpper(id)
	if strings.HasPrefix(upper, "CWE-") {
		return upper
	}
	return "CWE-" + id
}

func Lookup(id string) (*CWERecord, bool) {
	initCWEMap()
	if cweError != nil {
		return nil, false
	}
	r, ok := cweMap[normalizeID(id)]
	return r, ok
}
