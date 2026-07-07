package format

import "testing"

func TestAppendReferrerTag(t *testing.T) {
	cases := []struct {
		name string
		url  string
		tag  string
		want string
	}{
		{"empty tag", "https://example.com/path", "", "https://example.com/path"},
		{"empty url", "", "myreport", ""},
		{"no existing query", "https://example.com/path", "myreport", "https://example.com/path?ref=myreport"},
		{"merges existing query", "https://example.com/path?a=1", "myreport", "https://example.com/path?a=1&ref=myreport"},
		{"overwrites existing ref", "https://example.com/path?ref=old", "myreport", "https://example.com/path?ref=myreport"},
		{"malformed url unchanged", "http://[::1]:namedport", "myreport", "http://[::1]:namedport"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendReferrerTag(tc.url, tc.tag)
			if got != tc.want {
				t.Errorf("appendReferrerTag(%q, %q) = %q, want %q", tc.url, tc.tag, got, tc.want)
			}
		})
	}
}
