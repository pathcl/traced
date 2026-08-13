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

// TestQueryOrphanCreators_withMockTraces exercises the full pipeline for the
// "service creates fresh traceparents" scenario:
//
//	testutil.TraceBuilder → OTLP JSON → httptest → FetchTrace → BuildTree
//	→ SaveSpans → QueryOrphanCreators
//
// Scenario:
//
//   - 20 complete traces: frontend → api-gateway → payment-svc → billing-svc
//     (api-gateway appears as a callee in all of them)
//
//   - 6 orphan traces initiated by api-gateway: api-gateway → payment-svc → billing-svc
//     (api-gateway created a fresh traceparent — it's a root WITH children)
//
//   - 3 leaf orphan traces from billing-svc (no children):
//     billing-svc started a root trace with no downstream calls
//     (receiving_drop pattern — its caller dropped traceparent)
//
// Expected QueryOrphanCreators result: api-gateway only.
// billing-svc is a leaf root (receiving_drop), not an orphan creator.
func TestQueryOrphanCreators_withMockTraces(t *testing.T) {
	corpus := buildOrphanCorpus()

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

	creators, err := s.QueryOrphanCreators(context.Background())
	if err != nil {
		t.Fatalf("QueryOrphanCreators: %v", err)
	}

	t.Logf("orphan creators found: %d", len(creators))
	for _, c := range creators {
		t.Logf("  service=%s  as_callee=%d  orphan_root=%d  leaf_root=%d",
			c.Service, c.TracesAsCallee, c.TracesAsOrphanRoot, c.TracesAsLeafRoot)
	}

	byService := map[string]OrphanCreator{}
	for _, c := range creators {
		byService[c.Service] = c
	}

	// api-gateway: appears as callee in 20 complete traces, orphan root in 6.
	gw, ok := byService["api-gateway"]
	if !ok {
		t.Fatal("expected api-gateway to be detected as an orphan creator")
	}
	if gw.TracesAsCallee != 20 {
		t.Errorf("api-gateway: want 20 traces as callee, got %d", gw.TracesAsCallee)
	}
	if gw.TracesAsOrphanRoot != 6 {
		t.Errorf("api-gateway: want 6 orphan root traces, got %d", gw.TracesAsOrphanRoot)
	}

	// billing-svc: appears as a leaf root (receiving_drop), NOT an orphan creator.
	// QueryOrphanCreators should NOT return it because its root spans have no children.
	if _, found := byService["billing-svc"]; found {
		t.Error("billing-svc is a leaf orphan (receiving_drop), should NOT appear in orphan creators")
	}
}

func buildOrphanCorpus() map[string][]byte {
	corpus := make(map[string][]byte)

	// 20 complete traces: frontend → api-gateway → payment-svc → billing-svc.
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("complete-%02d", i)
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "frontend", "GET /checkout",
				map[string]string{"tenant": "acme"}).
			AddSpan("s2", "s1", "api-gateway", "route",
				map[string]string{"tenant": "acme"}).
			AddSpan("s3", "s2", "payment-svc", "charge",
				map[string]string{"tenant": "acme"}).
			AddSpan("s4", "s3", "billing-svc", "record",
				map[string]string{"tenant": "acme"}).
			MustJSON()
	}

	// 6 orphan traces where api-gateway created a new traceparent.
	// api-gateway is the root and it called payment-svc → billing-svc under the new context.
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("orphan-gw-%02d", i)
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "api-gateway", "route",
				map[string]string{}).
			AddSpan("s2", "s1", "payment-svc", "charge",
				map[string]string{}).
			AddSpan("s3", "s2", "billing-svc", "record",
				map[string]string{}).
			MustJSON()
	}

	// 3 leaf orphan traces from billing-svc (receiving_drop — its caller dropped traceparent).
	// billing-svc has no children in these traces.
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("leaf-billing-%02d", i)
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "billing-svc", "record",
				map[string]string{}).
			MustJSON()
	}

	return corpus
}
