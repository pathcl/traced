package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pathcl/traced/internal/tempo"
	"github.com/pathcl/traced/internal/testutil"
)

// TestQueryBaggageCoverage_withMockTraces exercises the full pipeline:
//
//	testutil.TraceBuilder → OTLP JSON → httptest → FetchTrace → BuildTree
//	→ SaveSpans → QueryBaggageCoverage
//
// Scenario: frontend → api-gateway → billing-svc → payment-svc
//
//   - frontend:    injects tenant + country (entry point, coverage not meaningful)
//   - api-gateway: carries tenant + country on every span (100% coverage)
//   - billing-svc: carries nothing — not doing context propagation (0% coverage, middleware)
//   - payment-svc: carries nothing — also no propagation but is a leaf (0%, not middleware)
func TestQueryBaggageCoverage_withMockTraces(t *testing.T) {
	corpus := buildCoverageCorpus()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/traces/")
		data, ok := corpus[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	t.Cleanup(srv.Close)

	client := tempo.NewClient(srv.URL, "")

	var trees [][]*tempo.Span
	for id := range corpus {
		raw, err := client.FetchTrace(context.Background(), id)
		if err != nil {
			t.Fatalf("FetchTrace(%q): %v", id, err)
		}
		if roots := tempo.BuildTree(raw); len(roots) > 0 {
			trees = append(trees, roots)
		}
	}

	s := openTestStore(t)
	if err := s.SaveSpans(context.Background(), "tick-1", trees); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	coverage, err := s.QueryBaggageCoverage(context.Background())
	if err != nil {
		t.Fatalf("QueryBaggageCoverage: %v", err)
	}

	t.Logf("coverage results: %d services", len(coverage))
	for _, c := range coverage {
		t.Logf("  %-20s  spans=%d  with_baggage=%d  coverage=%.0f%%  middleware=%v",
			c.Service, c.TotalSpans, c.WithBaggage, c.Coverage*100, c.IsMiddleware)
	}

	byService := map[string]ServiceCoverage{}
	for _, c := range coverage {
		byService[c.Service] = c
	}

	// api-gateway: 100% coverage, IS middleware (has callers above and callees below).
	gw := byService["api-gateway"]
	if gw.Coverage < 0.99 {
		t.Errorf("api-gateway: want ~100%% coverage, got %.2f", gw.Coverage)
	}
	if !gw.IsMiddleware {
		t.Error("api-gateway: expected IsMiddleware=true")
	}

	// billing-svc: 0% coverage, IS middleware (called by api-gateway, calls payment-svc).
	billing := byService["billing-svc"]
	if billing.Coverage > 0.01 {
		t.Errorf("billing-svc: want 0%% coverage, got %.2f", billing.Coverage)
	}
	if !billing.IsMiddleware {
		t.Error("billing-svc: expected IsMiddleware=true (it calls payment-svc)")
	}

	// payment-svc: 0% coverage, NOT middleware (it's a leaf — no downstream calls).
	payment := byService["payment-svc"]
	if payment.Coverage > 0.01 {
		t.Errorf("payment-svc: want 0%% coverage, got %.2f", payment.Coverage)
	}
	if payment.IsMiddleware {
		t.Error("payment-svc: expected IsMiddleware=false (leaf service, no children)")
	}

	// Results should be sorted by coverage ascending — zero-coverage services first.
	for i := 1; i < len(coverage); i++ {
		if coverage[i].Coverage < coverage[i-1].Coverage {
			t.Errorf("results not sorted by coverage ascending at index %d", i)
		}
	}
}

func buildCoverageCorpus() map[string][]byte {
	corpus := make(map[string][]byte, 15)
	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("trace-%02d", i)
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "frontend", "GET /checkout",
				map[string]string{"tenant": "acme", "country": "es"}).
			AddSpan("s2", "s1", "api-gateway", "route",
				map[string]string{"tenant": "acme", "country": "es"}).
			// billing-svc: no baggage — not extracting or propagating
			AddSpan("s3", "s2", "billing-svc", "charge",
				map[string]string{}).
			// payment-svc: also no baggage — leaf, so not middleware
			AddSpan("s4", "s3", "payment-svc", "record",
				map[string]string{}).
			MustJSON()
	}
	return corpus
}
