package format_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schema is a pinned copy of GitLab's dast-report-format.json; bump it
// together with format.GitLabSchemaVersion.
const gitlabSchemaFile = "testdata/gitlab-dast-report-format-15.2.5.json"

func compileGitLabSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(gitlabSchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://gitlab.example/dast-report-format.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateGitLab(t *testing.T, schema *jsonschema.Schema, data []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Errorf("output does not match the GitLab DAST schema %s:\n%v\n%s", format.GitLabSchemaVersion, err, data)
	}
}

func TestGitLabSchemaFileMatchesPinnedVersion(t *testing.T) {
	raw, err := os.ReadFile(gitlabSchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Self struct {
			Version string `json:"version"`
		} `json:"self"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.Self.Version != format.GitLabSchemaVersion {
		t.Errorf("schema file is %s, GitLabSchemaVersion is %s", s.Self.Version, format.GitLabSchemaVersion)
	}
}

func TestGitLabGolden(t *testing.T) {
	data, err := format.NewGitLabFormatter().Format(goldenReport())
	if err != nil {
		t.Fatal(err)
	}
	validateGitLab(t, compileGitLabSchema(t), data)
	assertGolden(t, "report.gitlab.json", data)
}

func TestGitLabValidatesEdgeCases(t *testing.T) {
	schema := compileGitLabSchema(t)
	cases := map[string]*reportx.Report{
		"empty":    emptyReport(),
		"minimal":  {Findings: []reportx.Finding{minimalFinding()}},
		"fixtures": fullReport(),
		"rich":     {ToolName: "T", ToolVersion: "1", Findings: []reportx.Finding{richFinding()}},
		"no tool, odd severity": {Findings: []reportx.Finding{
			{Title: strings.Repeat("x", 300), Severity: "bogus", URL: "not a url"},
		}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := format.NewGitLabFormatter().Format(r)
			if err != nil {
				t.Fatal(err)
			}
			validateGitLab(t, schema, data)
		})
	}
}

func TestGitLabMapping(t *testing.T) {
	data, _ := format.NewGitLabFormatter().Format(goldenReport())
	var out struct {
		Version string `json:"version"`
		Scan    struct {
			Status   string `json:"status"`
			Type     string `json:"type"`
			Messages []struct {
				Level string `json:"level"`
			} `json:"messages"`
		} `json:"scan"`
		Vulnerabilities []struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Identifiers []struct {
				Type, Value string
			} `json:"identifiers"`
			Location struct {
				Hostname, Path, Param string
			} `json:"location"`
			Flags []struct{ Type string } `json:"flags"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != format.GitLabSchemaVersion || out.Scan.Type != "dast" || out.Scan.Status != "failure" {
		t.Errorf("version/type/status = %s/%s/%s", out.Version, out.Scan.Type, out.Scan.Status)
	}
	if len(out.Scan.Messages) != 1 {
		t.Errorf("scan errors should become scan messages, got %d", len(out.Scan.Messages))
	}
	first := out.Vulnerabilities[0]
	if first.Severity != "Critical" || first.Identifiers[0].Type != "cwe" || first.Identifiers[0].Value != "89" {
		t.Errorf("first vulnerability = %+v", first)
	}
	if first.Location.Hostname != "https://api.example.com" || first.Location.Path != "/auth/login" || first.Location.Param != "username" {
		t.Errorf("location = %+v", first.Location)
	}
	var flagged int
	for _, v := range out.Vulnerabilities {
		for _, f := range v.Flags {
			if f.Type == "flagged-as-likely-false-positive" {
				flagged++
			}
		}
	}
	if flagged != 1 {
		t.Errorf("false-positive flags = %d, want 1", flagged)
	}
}
