package format

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/evidence"
)

// GitLabSchemaVersion is the version of GitLab's DAST report schema
// (dast-report-format.json) that GitLabFormatter targets. Tests validate the
// output against a pinned copy of that schema.
const GitLabSchemaVersion = "15.2.5"

// GitLabFormatter renders a report as a GitLab DAST security report, so
// findings appear in merge requests and the security dashboard when the file
// is published as a `dast` report artifact.
type GitLabFormatter struct{}

func NewGitLabFormatter() *GitLabFormatter { return &GitLabFormatter{} }

type gitlabReport struct {
	Version         string       `json:"version"`
	Scan            gitlabScan   `json:"scan"`
	Vulnerabilities []gitlabVuln `json:"vulnerabilities"`
}

type gitlabScan struct {
	Analyzer         gitlabTool       `json:"analyzer"`
	Scanner          gitlabTool       `json:"scanner"`
	StartTime        string           `json:"start_time"`
	EndTime          string           `json:"end_time"`
	Status           string           `json:"status"`
	Type             string           `json:"type"`
	ScannedResources []gitlabResource `json:"scanned_resources"`
	Messages         []gitlabMessage  `json:"messages,omitempty"`
}

type gitlabTool struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	URL     string       `json:"url,omitempty"`
	Version string       `json:"version"`
	Vendor  gitlabVendor `json:"vendor"`
}

type gitlabVendor struct {
	Name string `json:"name"`
}

type gitlabResource struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Type   string `json:"type"`
}

type gitlabMessage struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

type gitlabVuln struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity"`
	Solution    string             `json:"solution,omitempty"`
	Identifiers []gitlabIdentifier `json:"identifiers"`
	CVSSVectors []gitlabCVSS       `json:"cvss_vectors,omitempty"`
	Links       []gitlabLink       `json:"links,omitempty"`
	Flags       []gitlabFlag       `json:"flags,omitempty"`
	Evidence    *gitlabEvidence    `json:"evidence,omitempty"`
	Location    gitlabLocation     `json:"location"`
}

type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type gitlabCVSS struct {
	Vendor string `json:"vendor"`
	Vector string `json:"vector"`
}

type gitlabLink struct {
	URL string `json:"url"`
}

type gitlabFlag struct {
	Type        string `json:"type"`
	Origin      string `json:"origin"`
	Description string `json:"description"`
}

type gitlabLocation struct {
	Hostname string `json:"hostname,omitempty"`
	Method   string `json:"method,omitempty"`
	Param    string `json:"param,omitempty"`
	Path     string `json:"path,omitempty"`
}

type gitlabEvidence struct {
	Source   *gitlabEvidenceSource `json:"source,omitempty"`
	Request  *gitlabHTTPRequest    `json:"request,omitempty"`
	Response *gitlabHTTPResponse   `json:"response,omitempty"`
}

type gitlabEvidenceSource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type gitlabHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type gitlabHTTPRequest struct {
	Headers []gitlabHeader `json:"headers"`
	Method  string         `json:"method"`
	URL     string         `json:"url"`
	Body    string         `json:"body,omitempty"`
}

type gitlabHTTPResponse struct {
	Headers      []gitlabHeader `json:"headers"`
	ReasonPhrase string         `json:"reason_phrase"`
	StatusCode   int            `json:"status_code"`
	Body         string         `json:"body,omitempty"`
}

var (
	gitlabURLPattern = regexp.MustCompile(`^(https?|ftp)://.+`)
	gitlabSlugRe     = regexp.MustCompile(`[^a-z0-9]+`)
)

func gitlabSeverity(s reportx.Severity) string {
	switch s {
	case reportx.SeverityCritical:
		return "Critical"
	case reportx.SeverityHigh:
		return "High"
	case reportx.SeverityMedium:
		return "Medium"
	case reportx.SeverityLow:
		return "Low"
	case reportx.SeverityInfo:
		return "Info"
	default:
		return "Unknown"
	}
}

func gitlabSlug(s string) string {
	slug := strings.Trim(gitlabSlugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if slug == "" {
		return "unknown"
	}
	return slug
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func gitlabIdentifiers(fi reportx.Finding, tool string) []gitlabIdentifier {
	var ids []gitlabIdentifier
	if fi.CWEID != "" {
		value := strings.TrimPrefix(strings.ToUpper(fi.CWEID), "CWE-")
		id := gitlabIdentifier{Type: "cwe", Name: fi.CWEID, Value: value}
		if strings.Trim(value, "0123456789") == "" {
			id.URL = "https://cwe.mitre.org/data/definitions/" + value + ".html"
		}
		ids = append(ids, id)
	}
	if fi.OwaspTop10 != "" {
		ids = append(ids, gitlabIdentifier{Type: "owasp", Name: fi.OwaspTop10, Value: fi.OwaspTop10})
	}
	if len(ids) == 0 {
		// GitLab requires at least one identifier; fall back to the producer's own.
		value := nonEmpty(fi.ID, nonEmpty(fi.Title, "unknown"))
		ids = append(ids, gitlabIdentifier{Type: gitlabSlug(tool), Name: nonEmpty(fi.Title, value), Value: value})
	}
	return ids
}

func gitlabHeaders(h map[string][]string) []gitlabHeader {
	keys := sortedKeys(h)
	out := make([]gitlabHeader, 0, len(keys))
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, gitlabHeader{Name: k, Value: v})
		}
	}
	return out
}

func gitlabEvidenceFor(fi reportx.Finding, tool string) *gitlabEvidence {
	ev, ok := fi.Evidence.(*evidence.HTTPEvidence)
	if !ok || ev == nil {
		return nil
	}
	out := &gitlabEvidence{Source: &gitlabEvidenceSource{ID: gitlabSlug(tool), Name: tool}}
	if ev.RequestMethod != "" && ev.RequestURL != "" {
		out.Request = &gitlabHTTPRequest{
			Headers: gitlabHeaders(ev.RequestHeaders),
			Method:  ev.RequestMethod,
			URL:     ev.RequestURL,
			Body:    string(ev.RequestBody),
		}
	}
	if ev.ResponseStatus != 0 {
		out.Response = &gitlabHTTPResponse{
			Headers:      gitlabHeaders(ev.ResponseHeaders),
			ReasonPhrase: http.StatusText(ev.ResponseStatus),
			StatusCode:   ev.ResponseStatus,
			Body:         string(ev.ResponseBody),
		}
	}
	if out.Request == nil && out.Response == nil {
		return nil
	}
	return out
}

func gitlabLocationFor(fi reportx.Finding) gitlabLocation {
	loc := gitlabLocation{Param: fi.Parameter}
	if ev, ok := fi.Evidence.(*evidence.HTTPEvidence); ok && ev != nil {
		loc.Method = ev.RequestMethod
	}
	if u, err := url.Parse(fi.URL); err == nil && u.Host != "" {
		loc.Hostname = u.Scheme + "://" + u.Host
		loc.Path = u.EscapedPath()
	}
	return loc
}

func (f *GitLabFormatter) Format(r *reportx.Report) ([]byte, error) {
	tool := nonEmpty(r.ToolName, "unknown")
	toolInfo := gitlabTool{
		ID:      gitlabSlug(tool),
		Name:    tool,
		Version: nonEmpty(r.ToolVersion, "unknown"),
		Vendor:  gitlabVendor{Name: tool},
	}

	ts := r.ScanDate.UTC().Format("2006-01-02T15:04:05")
	status := "success"
	if len(r.Errors) > 0 || r.Coverage.Errored > 0 {
		status = "failure"
	}

	resources := []gitlabResource{}
	seen := map[string]bool{}
	addResource := func(method, u string) {
		if !gitlabURLPattern.MatchString(u) {
			return
		}
		key := method + " " + u
		if seen[key] {
			return
		}
		seen[key] = true
		resources = append(resources, gitlabResource{Method: method, URL: u, Type: "url"})
	}
	addResource("GET", r.Target)

	vulns := make([]gitlabVuln, 0, len(r.Findings))
	for _, fi := range r.Findings {
		loc := gitlabLocationFor(fi)
		addResource(nonEmpty(loc.Method, "GET"), fi.URL)

		v := gitlabVuln{
			ID:          nonEmpty(fi.ID, nonEmpty(fi.FingerprintHash, fi.Title)),
			Name:        truncate(fi.Title, 255),
			Description: fi.Description,
			Severity:    gitlabSeverity(fi.Severity),
			Solution:    fi.Remediation,
			Identifiers: gitlabIdentifiers(fi, tool),
			Evidence:    gitlabEvidenceFor(fi, tool),
			Location:    loc,
		}
		for _, ref := range fi.References {
			if gitlabURLPattern.MatchString(ref) {
				v.Links = append(v.Links, gitlabLink{URL: ref})
			}
		}
		if fi.CVSS31Vector != "" {
			v.CVSSVectors = append(v.CVSSVectors, gitlabCVSS{Vendor: tool, Vector: fi.CVSS31Vector})
		}
		if fi.CVSS40Vector != "" {
			v.CVSSVectors = append(v.CVSSVectors, gitlabCVSS{Vendor: tool, Vector: fi.CVSS40Vector})
		}
		if fi.Status == reportx.StatusFalsePositive {
			v.Flags = append(v.Flags, gitlabFlag{
				Type:        "flagged-as-likely-false-positive",
				Origin:      tool,
				Description: "Marked as a false positive in the " + tool + " report.",
			})
		}
		vulns = append(vulns, v)
	}

	scan := gitlabScan{
		Analyzer:         toolInfo,
		Scanner:          toolInfo,
		StartTime:        ts,
		EndTime:          ts,
		Status:           status,
		Type:             "dast",
		ScannedResources: resources,
	}
	for _, e := range r.Errors {
		msg := e.Message
		if e.CheckID != "" {
			msg = e.CheckID + ": " + msg
		}
		if e.Resource != "" {
			msg += " (" + e.Resource + ")"
		}
		scan.Messages = append(scan.Messages, gitlabMessage{Level: "warn", Value: msg})
	}

	return json.MarshalIndent(gitlabReport{
		Version:         GitLabSchemaVersion,
		Scan:            scan,
		Vulnerabilities: vulns,
	}, "", "  ")
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

func (f *GitLabFormatter) MediaType() string     { return "application/json" }
func (f *GitLabFormatter) FileExtension() string { return ".gl-dast-report.json" }

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
