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

// TestQueryBaggageDrops_withMockTraces runs the full pipeline:
//
//	testutil.TraceBuilder → OTLP JSON → httptest → FetchTrace → BuildTree
//	→ SaveSpans → QueryBaggageDrops
//
// Scenario: frontend → api-gateway → payment-svc → billing-svc
//
//   - tenant and country are injected at the frontend
//   - api-gateway → payment-svc: country drops intermittently (3/10 calls)
//   - payment-svc → billing-svc: both tenant AND country drop every call
//     (systematic misconfiguration — baggage propagation not enabled)
func TestQueryBaggageDrops_withMockTraces(t *testing.T) {
	corpus := buildCorpus()

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

	// Fetch every trace, build its span tree, collect into a flat slice.
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

	if len(trees) != len(corpus) {
		t.Fatalf("expected %d trees, got %d", len(corpus), len(trees))
	}

	s := openTestStore(t)
	if err := s.SaveSpans(context.Background(), "tick-1", trees); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	drops, err := s.QueryBaggageDrops(context.Background(), true)
	if err != nil {
		t.Fatalf("QueryBaggageDrops: %v", err)
	}

	// Index results by edge+key for easy assertions.
	type edgeKey struct{ caller, callee, key string }
	byEdge := map[edgeKey]BaggageDrop{}
	for _, d := range drops {
		byEdge[edgeKey{d.Caller, d.Callee, d.DroppedKey}] = d
	}

	t.Logf("drops found: %d", len(drops))
	for _, d := range drops {
		t.Logf("  %s → %s | %s: %d/%d (%.1f%%)",
			d.Caller, d.Callee, d.DroppedKey, d.TimesDropped, d.TotalCalls, d.DropPct)
	}

	// --- payment-svc → billing-svc: systematic drop of tenant (all 10 calls) ---
	pbTenant := byEdge[edgeKey{"payment-svc", "billing-svc", "tenant"}]
	if pbTenant.TimesDropped != 10 {
		t.Errorf("payment→billing/tenant: want 10 drops, got %d", pbTenant.TimesDropped)
	}
	if pbTenant.DropPct != 100 {
		t.Errorf("payment→billing/tenant: want 100%% drop rate, got %.1f%%", pbTenant.DropPct)
	}

	// country drops at payment→billing only for the 7 traces where api-gateway
	// forwarded it. In the 3 traces where api-gateway already dropped it,
	// payment-svc never had country to forward — so those 3 are attributed to
	// the api-gateway→payment edge, not here. This is correct: drops are
	// attributed to the first edge where they occur.
	pbCountry := byEdge[edgeKey{"payment-svc", "billing-svc", "country"}]
	if pbCountry.TimesDropped != 7 {
		t.Errorf("payment→billing/country: want 7 drops (only traces where payment had country), got %d", pbCountry.TimesDropped)
	}

	// --- api-gateway → payment-svc: intermittent country drop (3/10) ---
	apCountry := byEdge[edgeKey{"api-gateway", "payment-svc", "country"}]
	if apCountry.TimesDropped != 3 {
		t.Errorf("api-gateway→payment/country: want 3 drops, got %d", apCountry.TimesDropped)
	}
	if apCountry.TotalCalls != 10 {
		t.Errorf("api-gateway→payment/country: want 10 total calls, got %d", apCountry.TotalCalls)
	}

	// --- api-gateway → payment-svc: tenant should NOT drop ---
	apTenant, hasTenantDrop := byEdge[edgeKey{"api-gateway", "payment-svc", "tenant"}]
	if hasTenantDrop && apTenant.TimesDropped > 0 {
		t.Errorf("api-gateway→payment/tenant: should not drop, got %d drops", apTenant.TimesDropped)
	}

	// --- frontend → api-gateway: no drops at all ---
	for k, d := range byEdge {
		if k.caller == "frontend" && k.callee == "api-gateway" {
			t.Errorf("frontend→api-gateway should have no drops, got: %+v", d)
		}
	}
}

// buildCorpus creates 10 complete traces for the scenario described above.
//
// Trace structure:
//
//	frontend(tenant, country) → api-gateway(tenant, country)
//	  → payment-svc(tenant, country|dropped-country) → billing-svc(no tenant, no country)
//
// Traces 0-6: all four attributes propagate through to payment-svc.
// Traces 7-9: api-gateway drops country before payment-svc (intermittent).
// All 10:     payment-svc never forwards tenant or country to billing-svc.
func buildCorpus() map[string][]byte {
	corpus := make(map[string][]byte, 10)

	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("trace-%02d", i)

		paymentAttrs := map[string]string{"tenant": "acme", "country": "es"}
		if i >= 7 {
			// api-gateway dropped country before this call arrived
			delete(paymentAttrs, "country")
		}

		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "frontend", "GET /checkout",
				map[string]string{"tenant": "acme", "country": "es"}).
			AddSpan("s2", "s1", "api-gateway", "route",
				map[string]string{"tenant": "acme", "country": "es"}).
			AddSpan("s3", "s2", "payment-svc", "charge", paymentAttrs).
			// billing-svc never propagates — systematic misconfiguration
			AddSpan("s4", "s3", "billing-svc", "record",
				map[string]string{}).
			MustJSON()
	}

	return corpus
}
