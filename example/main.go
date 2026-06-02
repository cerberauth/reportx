package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/dedup"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/format"
)

func initTracer(ctx context.Context) (shutdown func(context.Context) error, err error) {
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("init stdout exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

const loginURL = "https://api.example.com/auth/login"

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	shutdown, err := initTracer(ctx)
	if err != nil {
		return fmt.Errorf("init tracer: %v", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			log.Printf("tracer shutdown: %v", err)
		}
	}()

	flags := format.RegisterFlags(flag.CommandLine)
	doEnrich := flag.Bool("enrich", false, "auto-fill CWE names and OWASP Top 10 tags")
	doDedup := flag.Bool("dedup", false, "remove duplicate findings by fingerprint hash")
	flag.Parse()

	now := time.Now()
	findings := []reportx.Finding{
		{
			ID:           "F-001",
			Title:        "SQL Injection in login endpoint",
			Severity:     reportx.SeverityCritical,
			CVSS31Score:  9.8,
			CVSS31Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWEID:        "CWE-89",
			URL:          loginURL,
			Parameter:    "username",
			Evidence: reportx.Evidence{
				RawRequest:     "POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"' OR 1=1--\",\"password\":\"x\"}",
				RawResponse:    "HTTP/1.1 500 Internal Server Error\r\n\r\nSQLite error: near \"OR\": syntax error",
				RequestMethod:  "POST",
				RequestURL:     loginURL,
				ResponseStatus: 500,
				RequestBody:    []byte(`{"username":"' OR 1=1--","password":"x"}`),
				ResponseBody:   []byte("SQLite error: near \"OR\": syntax error"),
			},
			Description: "The login endpoint passes the username parameter directly into a SQL query without sanitization, allowing an attacker to manipulate the query logic.",
			Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
			FirstSeen:   now.Add(-72 * time.Hour),
			LastSeen:    now,
			Status:      reportx.StatusActive,
			Tags:        []string{"injection", "auth", "critical-path"},
			Extra:       map[string]string{"scanner": "example", "alert-ref": "40018"},
		},
		{
			ID:          "F-002",
			Title:       "SQL Injection in login endpoint (rescan)",
			Severity:    reportx.SeverityCritical,
			CWEID:       "CWE-89",
			URL:         loginURL,
			Parameter:   "username",
			Description: "Same vulnerability re-detected during the follow-up scan. Deduplicate to merge with F-001.",
			Status:      reportx.StatusActive,
		},
		{
			ID:          "F-003",
			Title:       "Reflected XSS in search parameter",
			Severity:    reportx.SeverityHigh,
			CVSS31Score: 7.2,
			CWEID:       "CWE-79",
			URL:         "https://api.example.com/search",
			Parameter:   "q",
			Evidence: reportx.Evidence{
				RawRequest:     "GET /search?q=<script>alert(document.domain)</script> HTTP/1.1",
				RawResponse:    "HTTP/1.1 200 OK\r\n\r\n...search: <script>alert(document.domain)</script>...",
				RequestMethod:  "GET",
				RequestURL:     "https://api.example.com/search?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E",
				ResponseStatus: 200,
				ResponseBody:   []byte("...search: <script>alert(document.domain)</script>..."),
			},
			Description: "User-supplied input in the 'q' parameter is reflected in the response body without HTML encoding.",
			Remediation: "HTML-encode all user-controlled output. Apply a strict Content-Security-Policy header.",
			FirstSeen:   now.Add(-48 * time.Hour),
			LastSeen:    now,
			Status:      reportx.StatusActive,
			Tags:        []string{"xss", "injection"},
		},
		{
			ID:          "F-004",
			Title:       "Server-Side Request Forgery via webhook URL",
			Severity:    reportx.SeverityHigh,
			CVSS31Score: 8.6,
			CWEID:       "CWE-918",
			URL:         "https://api.example.com/webhooks",
			Parameter:   "url",
			Description: "The webhook registration endpoint makes HTTP requests to attacker-controlled URLs without validating the destination, enabling internal network access.",
			Remediation: "Validate webhook destinations against an allowlist. Block requests to RFC-1918 address ranges and loopback interfaces.",
			FirstSeen:   now.Add(-24 * time.Hour),
			LastSeen:    now,
			Status:      reportx.StatusActive,
			Tags:        []string{"ssrf", "network"},
		},
		{
			ID:          "F-005",
			Title:       "Missing CSRF protection on account update",
			Severity:    reportx.SeverityMedium,
			CVSS31Score: 6.1,
			CWEID:       "CWE-352",
			URL:         "https://api.example.com/account/update",
			Description: "State-changing POST endpoints do not require a CSRF token, allowing cross-origin requests from attacker-controlled pages.",
			Remediation: "Implement the synchronizer token pattern or use the SameSite=Strict cookie attribute.",
			FirstSeen:   now.Add(-96 * time.Hour),
			LastSeen:    now,
			Status:      reportx.StatusAcceptedRisk,
			Tags:        []string{"csrf"},
			Extra:       map[string]string{"risk-accepted-by": "security-team", "ticket": "SEC-42"},
		},
		{
			ID:          "F-006",
			Title:       "Sensitive data exposed in profile response",
			Severity:    reportx.SeverityLow,
			CWEID:       "CWE-200",
			URL:         "https://api.example.com/users/profile",
			Description: "The profile endpoint includes internal fields (e.g. password_hash, internal_id) in the JSON response that should not be visible to clients.",
			Remediation: "Use a response DTO that includes only the fields the client requires. Never serialize ORM objects directly.",
			FirstSeen:   now.Add(-12 * time.Hour),
			LastSeen:    now,
			Status:      reportx.StatusActive,
		},
		{
			ID:          "F-007",
			Title:       "Server version disclosed in response headers",
			Severity:    reportx.SeverityInfo,
			CWEID:       "CWE-200",
			URL:         "https://api.example.com/",
			Description: "The Server HTTP response header discloses the web server version (e.g. nginx/1.25.3), providing an attacker with reconnaissance information.",
			Remediation: "Configure the web server to suppress or replace the Server header.",
			FirstSeen:   now,
			LastSeen:    now,
			Status:      reportx.StatusFalsePositive,
			Tags:        []string{"information-disclosure", "headers"},
		},
	}

	builder := reportx.NewBuilder().
		Title("Example Security Scan").
		Tool("reportx-example", "1.0.0").
		Target("https://api.example.com").
		Findings(findings)

	if *doEnrich {
		builder = builder.Enrich(enrich.EnrichAll)
	}
	if *doDedup {
		builder = builder.Deduplicate(dedup.Deduplicate)
	}

	report, err := builder.Build(ctx)
	if err != nil {
		return fmt.Errorf("build report: %v", err)
	}

	formatter, err := flags.Formatter()
	if err != nil {
		return fmt.Errorf("invalid format: %v (available: json, jsonl, sarif, markdown, html, terminal)", err)
	}

	w, close, err := flags.Writer()
	if err != nil {
		return fmt.Errorf("open output: %v", err)
	}
	defer close()

	if err := report.WriteTo(ctx, w, formatter); err != nil {
		return fmt.Errorf("write report: %v", err)
	}

	return nil
}
