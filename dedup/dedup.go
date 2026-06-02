package dedup

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	"github.com/cerberauth/reportx"
)

func Fingerprint(f *reportx.Finding) string {
	cweID := normalizeField(f.CWEID)
	normalURL := normalizeURL(f.URL)
	param := normalizeField(f.Parameter)

	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", cweID, normalURL, param)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Deduplicate(findings []reportx.Finding) []reportx.Finding {
	out := make([]reportx.Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if f.FingerprintHash == "" {
			f.FingerprintHash = Fingerprint(&f)
		}
		if _, ok := seen[f.FingerprintHash]; ok {
			continue
		}
		seen[f.FingerprintHash] = struct{}{}
		out = append(out, f)
	}
	return out
}

func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || rawURL == "" {
		return strings.ToLower(strings.TrimRight(rawURL, "/"))
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	result := u.String()
	if len(u.Path) > 1 {
		result = strings.TrimRight(result, "/")
	}
	return result
}

func normalizeField(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
