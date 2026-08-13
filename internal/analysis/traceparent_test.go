package analysis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pathcl/traced/internal/tempo"
	"github.com/pathcl/traced/internal/testutil"
)

// TestTraceparentDrop_fullPipeline exercises the complete path:
//
//	OTLP JSON (httptest) → FetchTrace → BuildTree → DetectRootAnomalies
//
// The scenario: billing should always be a child of api. But in some
// requests the traceparent header is dropped before billing receives
// the call, so billing starts a brand-new root trace with its own
// traceID. Tempo stores these as completely separate, unrelated traces.
//
// We simulate 20 complete traces and 4 orphan billing roots, then assert
// that DetectRootAnomalies flags billing as suspicious.
func TestTraceparentDrop_fullPipeline(t *testing.T) {
	corpus := map[string][]byte{}

	const completeCount = 20
	const orphanCount = 4

	for i := 0; i < completeCount; i++ {
		id := fmt.Sprintf("complete-%d", i)
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "frontend", "GET /checkout",
				map[string]string{"tenant": "acme"}).
			AddSpan("s2", "s1", "api", "handle",
				map[string]string{"tenant": "acme"}).
			AddSpan("s3", "s2", "billing", "charge",
				map[string]string{"tenant": "acme"}).
			MustJSON()
	}

	for i := 0; i < orphanCount; i++ {
		id := fmt.Sprintf("orphan-%d", i)
		// billing starts its own root trace — it never received traceparent.
		corpus[id] = testutil.NewTrace(id).
			AddSpan("s1", "", "billing", "charge",
				map[string]string{}).
			MustJSON()
	}

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
			t.Fatalf("FetchTrace(%q) error: %v", id, err)
		}
		roots := tempo.BuildTree(raw)
		if len(roots) > 0 {
			trees = append(trees, roots)
		}
	}

	if len(trees) != completeCount+orphanCount {
		t.Fatalf("expected %d trees, got %d", completeCount+orphanCount, len(trees))
	}

	findings := DetectRootAnomalies(trees, 10, 0.001, time.Now())

	var billingFinding *RootAnomaly
	for i := range findings {
		if findings[i].Service == "billing" {
			billingFinding = &findings[i]
		}
	}
	if billingFinding == nil {
		t.Fatal("expected billing to be flagged as a root anomaly, but it was not")
	}

	// billing.AsCallee = 20 (complete traces), billing.AsRoot = 4 (orphans)
	// drop rate = 4/20 = 0.2
	if billingFinding.AsCallee != completeCount {
		t.Errorf("billing.AsCallee: want %d, got %d", completeCount, billingFinding.AsCallee)
	}
	if billingFinding.AsRoot != orphanCount {
		t.Errorf("billing.AsRoot: want %d, got %d", orphanCount, billingFinding.AsRoot)
	}
	wantRate := float64(orphanCount) / float64(completeCount)
	if billingFinding.DropRate < wantRate-0.01 || billingFinding.DropRate > wantRate+0.01 {
		t.Errorf("billing drop rate: want ~%.3f, got %.3f", wantRate, billingFinding.DropRate)
	}

	for _, f := range findings {
		if f.Service == "frontend" {
			t.Errorf("frontend should not be flagged: %+v", f)
		}
		if f.Service == "api" {
			t.Errorf("api should not be flagged: %+v", f)
		}
	}
}

// TestTraceparentDrop_baggageAlsoLost documents the relationship between the
// two detectors. When traceparent is dropped, the orphan span also loses
// baggage — but baggage drop detection requires a parent-child pair in the
// SAME trace. An orphan root has no parent in its trace, so DetectSpanAttributeDrops
// cannot see the drop. DetectRootAnomalies catches it instead.
//
// This test pins that boundary explicitly so the behaviour is intentional,
// not accidental.
func TestTraceparentDrop_baggageAlsoLost(t *testing.T) {
	completeTrace := testutil.NewTrace("t-complete").
		AddSpan("s1", "", "api", "handle", map[string]string{"tenant": "acme"}).
		AddSpan("s2", "s1", "billing", "charge", map[string]string{"tenant": "acme"}).
		MustJSON()

	// billing starts fresh: traceparent dropped, baggage gone too.
	orphanTrace := testutil.NewTrace("t-orphan").
		AddSpan("s1", "", "billing", "charge", map[string]string{}).
		MustJSON()

	corpus := map[string][]byte{
		"t-complete": completeTrace,
		"t-orphan":   orphanTrace,
	}

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
		trees = append(trees, tempo.BuildTree(raw))
	}

	// Root anomaly detector catches the orphan billing root.
	rootFindings := DetectRootAnomalies(trees, 1, 0.001, time.Now())
	foundRoot := false
	for _, f := range rootFindings {
		if f.Service == "billing" {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Error("DetectRootAnomalies: expected billing to be flagged as root anomaly")
	}

	// Baggage detector sees NO drop — the complete trace propagates tenant
	// correctly through api→billing, and the orphan has no parent to compare
	// against. This is correct and expected: the root anomaly finding IS the
	// signal for the baggage loss in this case.
	baggageFindings := DetectSpanAttributeDrops(trees, []string{"tenant"}, time.Now())
	for _, f := range baggageFindings {
		t.Errorf("unexpected baggage finding (orphan roots have no parent to diff against): %+v", f)
	}
}
