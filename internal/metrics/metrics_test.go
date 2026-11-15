package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func admTestHandler() http.Handler {
	return New(
		func() int64 { return 7 },
		func() uint64 { return 42 },
		func() int { return 3 },
		func() int64 { return 1_048_576 },
	)
}

func TestMetricsTextExposition(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	admTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE hexline_sessions_active gauge\nhexline_sessions_active 7\n",
		"# TYPE hexline_sessions_total counter\nhexline_sessions_total 42\n",
		"# TYPE hexline_online gauge\nhexline_online 3\n",
		"# TYPE hexline_db_bytes gauge\nhexline_db_bytes 1048576\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	admTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestUnknownPathAndMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	admTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec = httptest.NewRecorder()
	admTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d", rec.Code)
	}
}

func TestNilProbesReportZero(t *testing.T) {
	h := New(nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, name := range []string{"hexline_sessions_active", "hexline_sessions_total", "hexline_online", "hexline_db_bytes"} {
		if !strings.Contains(text, name+" 0\n") {
			t.Errorf("nil probe %s did not report 0:\n%s", name, text)
		}
	}
}

func TestEscaping(t *testing.T) {
	if got, want := escapeLabelValue("a\\b\"c\nd"), `a\\b\"c\nd`; got != want {
		t.Fatalf("escapeLabelValue = %q, want %q", got, want)
	}
	if got, want := escapeHelp("line one\nline two"), `line one\nline two`; got != want {
		t.Fatalf("escapeHelp = %q, want %q", got, want)
	}
}
