package format

import "net/url"

// appendReferrerTag merges a "ref" query param into rawURL so a report
// reader's click can be attributed back to reportx. Returns rawURL
// unchanged if tag or rawURL is empty, or if rawURL fails to parse.
func appendReferrerTag(rawURL, tag string) string {
	if tag == "" || rawURL == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("ref", tag)
	u.RawQuery = q.Encode()
	return u.String()
}
