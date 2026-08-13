package tempo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pathcl/traced/internal/testutil"
)

// newTestServer starts an httptest server with the given handler and returns a
// client pointed at it. Caller is responsible for calling srv.Close().
func newTestServer(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, ""), srv
}

func TestSearch_returnsTraceIDs(t *testing.T) {
	want := testutil.NewSearchResponse().
		AddTrace("trace-abc", "frontend", "GET /checkout", 42).
		AddTrace("trace-def", "api-gateway", "POST /pay", 17).
		MustJSON()

	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/search" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(want)
	}))

	results, err := client.Search(context.Background(), `{}`,
		time.Now().Add(-10*time.Minute), time.Now(), 100)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].TraceID != "trace-abc" {
		t.Errorf("expected trace-abc, got %s", results[0].TraceID)
	}
	if results[1].RootServiceName != "api-gateway" {
		t.Errorf("expected api-gateway, got %s", results[1].RootServiceName)
	}
}

func TestSearch_passesQueryParams(t *testing.T) {
	var gotQuery, gotLimit string
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewSearchResponse().MustJSON())
	}))

	_, err := client.Search(context.Background(), `{span.tenant="acme"}`,
		time.Now().Add(-5*time.Minute), time.Now(), 42)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if gotQuery != `{span.tenant="acme"}` {
		t.Errorf("unexpected query param q=%q", gotQuery)
	}
	if gotLimit != "42" {
		t.Errorf("expected limit=42, got %q", gotLimit)
	}
}

func TestSearch_sendsOrgIDHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Scope-OrgID")
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewSearchResponse().MustJSON())
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "my-tenant")
	_, err := client.Search(context.Background(), `{}`,
		time.Now().Add(-5*time.Minute), time.Now(), 10)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if gotHeader != "my-tenant" {
		t.Errorf("expected X-Scope-OrgID=my-tenant, got %q", gotHeader)
	}
}

func TestSearch_omitsOrgIDHeaderWhenEmpty(t *testing.T) {
	var headerPresent bool
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerPresent = r.Header["X-Scope-Orgid"]
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewSearchResponse().MustJSON())
	}))

	_, err := client.Search(context.Background(), `{}`,
		time.Now().Add(-5*time.Minute), time.Now(), 10)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if headerPresent {
		t.Error("X-Scope-OrgID should not be set when tenantID is empty")
	}
}

func TestSearch_errorsOnNon200(t *testing.T) {
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))

	_, err := client.Search(context.Background(), `{}`,
		time.Now().Add(-5*time.Minute), time.Now(), 10)
	if err == nil {
		t.Error("expected error on HTTP 400, got nil")
	}
}

func TestFetchTrace_parsesOTLPSpans(t *testing.T) {
	traceJSON := testutil.NewTrace("trace-1").
		AddSpan("s1", "", "frontend", "GET /checkout", map[string]string{"tenant": "acme", "country": "es"}).
		AddSpan("s2", "s1", "billing", "charge", map[string]string{"tenant": "acme", "country": "es"}).
		MustJSON()

	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/traces/trace-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(traceJSON)
	}))

	spans, err := client.FetchTrace(context.Background(), "trace-1")
	if err != nil {
		t.Fatalf("FetchTrace returned error: %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}

	byID := map[string]RawSpan{}
	for _, s := range spans {
		byID[s.SpanID] = s
	}

	s1, ok := byID["s1"]
	if !ok {
		t.Fatal("span s1 not found")
	}
	if s1.Service != "frontend" {
		t.Errorf("expected service=frontend, got %s", s1.Service)
	}
	if s1.Attrs["tenant"] != "acme" {
		t.Errorf("expected tenant=acme, got %q", s1.Attrs["tenant"])
	}
	if s1.ParentSpanID != "" {
		t.Errorf("expected s1 to be root (no parent), got parentSpanID=%q", s1.ParentSpanID)
	}

	s2, ok := byID["s2"]
	if !ok {
		t.Fatal("span s2 not found")
	}
	if s2.Service != "billing" {
		t.Errorf("expected service=billing, got %s", s2.Service)
	}
	if s2.ParentSpanID != "s1" {
		t.Errorf("expected s2.parentSpanID=s1, got %q", s2.ParentSpanID)
	}
}

func TestFetchTrace_handlesOrphanedSpan(t *testing.T) {
	// billing arrives with a parentSpanID that has no corresponding span in the trace —
	// this simulates a dropped traceparent at the billing boundary.
	traceJSON := testutil.NewTrace("trace-2").
		AddSpan("s3", "missing-parent", "billing", "charge", map[string]string{}).
		MustJSON()

	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(traceJSON)
	}))

	spans, err := client.FetchTrace(context.Background(), "trace-2")
	if err != nil {
		t.Fatalf("FetchTrace returned error: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	// BuildTree should treat this as a root.
	roots := BuildTree(spans)
	if len(roots) != 1 {
		t.Fatalf("expected 1 root (orphan), got %d", len(roots))
	}
	if roots[0].Service != "billing" {
		t.Errorf("expected orphan root to be billing, got %s", roots[0].Service)
	}
}

func TestFetchTrace_errorsOnNon200(t *testing.T) {
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := client.FetchTrace(context.Background(), "does-not-exist")
	if err == nil {
		t.Error("expected error on HTTP 404, got nil")
	}
}
