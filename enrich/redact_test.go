package enrich_test

import (
	"reflect"
	"testing"

	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/evidence"
)

func masked(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = enrich.RedactedValue
	}
	return out
}

func assertHeader(t *testing.T, h map[string][]string, key string, want []string) {
	t.Helper()
	got, ok := h[key]
	if !ok {
		t.Fatalf("header %q missing", key)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("header %q = %v, want %v", key, got, want)
	}
}

func TestRedactCredentials_MasksDefaultHeaders(t *testing.T) {
	reqHeaders := map[string][]string{
		"Authorization":       {"Bearer abc"},
		"proxy-authorization": {"Basic xyz"},
		"COOKIE":              {"sid=1", "a=b"},
		"X-Api-Key":           {"k"},
		"Accept":              {"*/*"},
	}
	ev := &evidence.HTTPEvidence{
		RequestHeaders:  reqHeaders,
		ResponseHeaders: map[string][]string{"set-cookie": {"sid=2"}, "Content-Type": {"text/plain"}},
	}

	enrich.RedactCredentials(ev)

	assertHeader(t, ev.RequestHeaders, "Authorization", masked(1))
	assertHeader(t, ev.RequestHeaders, "proxy-authorization", masked(1))
	assertHeader(t, ev.RequestHeaders, "COOKIE", masked(2))
	assertHeader(t, ev.RequestHeaders, "X-Api-Key", masked(1))
	assertHeader(t, ev.RequestHeaders, "Accept", []string{"*/*"})
	assertHeader(t, ev.ResponseHeaders, "set-cookie", masked(1))
	assertHeader(t, ev.ResponseHeaders, "Content-Type", []string{"text/plain"})
	if reqHeaders["Authorization"][0] != "Bearer abc" {
		t.Error("caller map was mutated")
	}
}

func TestRedactCredentials_ExtraHeaders(t *testing.T) {
	ev := &evidence.HTTPEvidence{RequestHeaders: map[string][]string{"X-Custom-Token": {"s"}, "Accept": {"x"}}}

	enrich.RedactCredentials(ev, enrich.WithExtraHeaders("x-custom-token"))

	assertHeader(t, ev.RequestHeaders, "X-Custom-Token", masked(1))
	assertHeader(t, ev.RequestHeaders, "Accept", []string{"x"})
}

func TestRedactCredentials_RawDump(t *testing.T) {
	ev := &evidence.HTTPEvidence{
		RawRequest:  "GET / HTTP/1.1\r\nHost: a\r\nauthorization: Bearer abc\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\nSet-Cookie: sid=1\nContent-Length: 0\n",
	}

	enrich.RedactCredentials(ev)

	if want := "GET / HTTP/1.1\r\nHost: a\r\nauthorization: " + enrich.RedactedValue + "\r\n\r\n"; ev.RawRequest != want {
		t.Errorf("RawRequest = %q, want %q", ev.RawRequest, want)
	}
	if want := "HTTP/1.1 200 OK\nSet-Cookie: " + enrich.RedactedValue + "\nContent-Length: 0\n"; ev.RawResponse != want {
		t.Errorf("RawResponse = %q, want %q", ev.RawResponse, want)
	}
}

func TestRedactCredentials_BodyTruncation(t *testing.T) {
	ev := &evidence.HTTPEvidence{RequestBody: []byte("0123456789"), ResponseBody: []byte("abc")}

	enrich.RedactCredentials(ev, enrich.WithMaxBodySize(4))

	if got := string(ev.RequestBody); got != "0123... (truncated)" {
		t.Errorf("RequestBody = %q", got)
	}
	if got := string(ev.ResponseBody); got != "abc" {
		t.Errorf("ResponseBody = %q", got)
	}
}

func TestRedactCredentials_NoBodyCapByDefault(t *testing.T) {
	ev := &evidence.HTTPEvidence{ResponseBody: make([]byte, 1<<20)}

	enrich.RedactCredentials(ev)

	if len(ev.ResponseBody) != 1<<20 {
		t.Errorf("body truncated to %d bytes", len(ev.ResponseBody))
	}
}

func TestRedactCredentials_Disabled(t *testing.T) {
	ev := &evidence.HTTPEvidence{
		RequestHeaders: map[string][]string{"Authorization": {"Bearer abc"}},
		RequestBody:    []byte("0123456789"),
	}

	enrich.RedactCredentials(ev, enrich.WithDisabled(), enrich.WithMaxBodySize(2))

	assertHeader(t, ev.RequestHeaders, "Authorization", []string{"Bearer abc"})
	if string(ev.RequestBody) != "0123456789" {
		t.Errorf("RequestBody = %q", ev.RequestBody)
	}
}

func TestRedactCredentials_Nil(t *testing.T) {
	enrich.RedactCredentials(nil)
}
