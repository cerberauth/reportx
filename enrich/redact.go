package enrich

import (
	"strings"

	"github.com/cerberauth/reportx/evidence"
)

// RedactedValue replaces the value of every redacted header.
const RedactedValue = "***redacted***"

const truncatedSuffix = "... (truncated)"

var defaultRedactedHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
}

type redactConfig struct {
	headers     map[string]struct{}
	maxBodySize int
	disabled    bool
}

// RedactOption customizes RedactCredentials.
type RedactOption func(*redactConfig)

// WithExtraHeaders redacts additional header names, matched case-insensitively.
func WithExtraHeaders(names ...string) RedactOption {
	return func(c *redactConfig) {
		for _, n := range names {
			c.headers[strings.ToLower(n)] = struct{}{}
		}
	}
}

// WithMaxBodySize truncates bodies (and raw request/response dumps) to n bytes,
// appending "... (truncated)". Values of n <= 0 leave bodies untouched.
func WithMaxBodySize(n int) RedactOption {
	return func(c *redactConfig) { c.maxBodySize = n }
}

// WithDisabled turns redaction off, e.g. for local debugging.
func WithDisabled() RedactOption {
	return func(c *redactConfig) { c.disabled = true }
}

// RedactCredentials masks credential headers in ev in place. Header keys are
// kept so the report still shows they were set. Header maps are replaced with
// copies, so maps shared with the caller are not modified.
//
// Bodies are NOT scanned for secrets (tokens, passwords in JSON or form
// payloads); unless WithMaxBodySize is set they are kept verbatim, so callers
// writing reports to disk or sending them to a remote must handle that risk.
func RedactCredentials(ev *evidence.HTTPEvidence, opts ...RedactOption) {
	if ev == nil {
		return
	}
	cfg := &redactConfig{headers: make(map[string]struct{}, len(defaultRedactedHeaders))}
	for _, h := range defaultRedactedHeaders {
		cfg.headers[strings.ToLower(h)] = struct{}{}
	}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.disabled {
		return
	}

	ev.RequestHeaders = cfg.redactHeaders(ev.RequestHeaders)
	ev.ResponseHeaders = cfg.redactHeaders(ev.ResponseHeaders)
	ev.RawRequest = cfg.truncateString(cfg.redactRaw(ev.RawRequest))
	ev.RawResponse = cfg.truncateString(cfg.redactRaw(ev.RawResponse))
	ev.RequestBody = cfg.truncateBytes(ev.RequestBody)
	ev.ResponseBody = cfg.truncateBytes(ev.ResponseBody)
}

func (c *redactConfig) redactHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if _, ok := c.headers[strings.ToLower(k)]; !ok {
			out[k] = v
			continue
		}
		masked := make([]string, len(v))
		for i := range masked {
			masked[i] = RedactedValue
		}
		out[k] = masked
	}
	return out
}

// redactRaw masks "Name: value" lines of a raw HTTP dump.
func (c *redactConfig) redactRaw(raw string) string {
	if raw == "" {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, hit := c.headers[strings.ToLower(strings.TrimSpace(name))]; !hit {
			continue
		}
		cr := ""
		if strings.HasSuffix(line, "\r") {
			cr = "\r"
		}
		lines[i] = name + ": " + RedactedValue + cr
	}
	return strings.Join(lines, "\n")
}

func (c *redactConfig) truncateString(s string) string {
	if c.maxBodySize <= 0 || len(s) <= c.maxBodySize {
		return s
	}
	return s[:c.maxBodySize] + truncatedSuffix
}

func (c *redactConfig) truncateBytes(b []byte) []byte {
	if c.maxBodySize <= 0 || len(b) <= c.maxBodySize {
		return b
	}
	out := make([]byte, 0, c.maxBodySize+len(truncatedSuffix))
	out = append(out, b[:c.maxBodySize]...)
	return append(out, truncatedSuffix...)
}
