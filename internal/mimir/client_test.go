package mimir

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pathcl/traced/internal/testutil"
)

func newTestServer(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, ""), srv
}

func TestQuery_parsesVectorResult(t *testing.T) {
	body := testutil.NewMetricResponse().
		AddSample(map[string]string{"client": "frontend", "server": "api", "tenant": "acme"}, 42).
		AddSample(map[string]string{"client": "api", "server": "billing"}, 17).
		MustJSON()

	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))

	samples, err := client.Query(context.Background(),
		`count by (client,server,tenant)(traces_service_graph_request_total)`, time.Now())
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}

	// Find the sample with tenant label.
	var withTenant *Sample
	for i := range samples {
		if samples[i].Labels["tenant"] == "acme" {
			withTenant = &samples[i]
		}
	}
	if withTenant == nil {
		t.Fatal("expected a sample with tenant=acme")
	}
	if withTenant.Labels["client"] != "frontend" {
		t.Errorf("expected client=frontend, got %q", withTenant.Labels["client"])
	}
}

func TestQuery_passesPromQLParam(t *testing.T) {
	var gotQuery string
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewMetricResponse().MustJSON())
	}))

	expr := `count by (client, server) (traces_service_graph_request_total)`
	_, err := client.Query(context.Background(), expr, time.Now())
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if gotQuery != expr {
		t.Errorf("expected query=%q, got %q", expr, gotQuery)
	}
}

func TestQuery_sendsOrgIDHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Scope-OrgID")
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewMetricResponse().MustJSON())
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "tenant-x")
	_, err := client.Query(context.Background(), `up`, time.Now())
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if gotHeader != "tenant-x" {
		t.Errorf("expected X-Scope-OrgID=tenant-x, got %q", gotHeader)
	}
}

func TestQuery_omitsOrgIDHeaderWhenEmpty(t *testing.T) {
	var headerPresent bool
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerPresent = r.Header["X-Scope-Orgid"]
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewMetricResponse().MustJSON())
	}))

	_, err := client.Query(context.Background(), `up`, time.Now())
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if headerPresent {
		t.Error("X-Scope-OrgID should not be set when tenantID is empty")
	}
}

func TestQuery_errorsOnNon200(t *testing.T) {
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	_, err := client.Query(context.Background(), `up`, time.Now())
	if err == nil {
		t.Error("expected error on HTTP 403, got nil")
	}
}

func TestLabelValues_returnsValues(t *testing.T) {
	body := testutil.NewLabelValuesResponse("acme", "globex", "umbrella")

	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/label/tenant/values" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))

	values, err := client.LabelValues(context.Background(), "tenant", "",
		time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("LabelValues returned error: %v", err)
	}
	if len(values) != 3 {
		t.Fatalf("expected 3 values, got %d: %v", len(values), values)
	}
	found := map[string]bool{}
	for _, v := range values {
		found[v] = true
	}
	for _, want := range []string{"acme", "globex", "umbrella"} {
		if !found[want] {
			t.Errorf("expected value %q in result", want)
		}
	}
}

func TestLabelValues_passesMatchParam(t *testing.T) {
	var gotMatch string
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMatch = r.URL.Query().Get("match[]")
		w.Header().Set("Content-Type", "application/json")
		w.Write(testutil.NewLabelValuesResponse())
	}))

	_, err := client.LabelValues(context.Background(), "tenant",
		`traces_service_graph_request_total`,
		time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("LabelValues returned error: %v", err)
	}
	if gotMatch != "traces_service_graph_request_total" {
		t.Errorf("expected match[]=traces_service_graph_request_total, got %q", gotMatch)
	}
}

func TestLabelValues_errorsOnNon200(t *testing.T) {
	client, _ := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	_, err := client.LabelValues(context.Background(), "tenant", "",
		time.Now().Add(-1*time.Hour), time.Now())
	if err == nil {
		t.Error("expected error on HTTP 500, got nil")
	}
}
