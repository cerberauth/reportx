package transport_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/transport"
)

func TestHTTPTransport_PostsFormattedReport(t *testing.T) {
	var gotContentType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := transport.NewHTTPTransport(srv.URL)
	f := format.NewJSONFormatter()
	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}

	if err := tr.Send(context.Background(), report, f); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody == "" {
		t.Error("request body was empty")
	}
}

func TestHTTPTransport_CustomHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr := transport.NewHTTPTransport(srv.URL)
	tr.Headers = map[string]string{"Authorization": "Bearer secret"}
	f := format.NewJSONFormatter()
	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}

	if err := tr.Send(context.Background(), report, f); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer secret")
	}
}

func TestHTTPTransport_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr := transport.NewHTTPTransport(srv.URL)
	f := format.NewJSONFormatter()
	report := &reportx.Report{Title: "test", Findings: []reportx.Finding{}}

	if err := tr.Send(context.Background(), report, f); err == nil {
		t.Error("expected error for 500 status, got nil")
	}
}
