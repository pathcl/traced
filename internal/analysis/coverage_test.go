package analysis

import (
	"testing"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

func span(svc string, attrs map[string]string, children ...*tempo.Span) *tempo.Span {
	s := &tempo.Span{Service: svc, Attrs: attrs, Children: children}
	for _, c := range children {
		c.ParentSpanID = "parent" // mark as callee
	}
	return s
}

func TestDetectNoCoverage_noBaggage(t *testing.T) {
	// billing-svc sits between api-gateway and payment-svc but carries no baggage.
	trees := [][]*tempo.Span{}
	for i := 0; i < 20; i++ {
		payment := span("payment-svc", map[string]string{})
		billing := span("billing-svc", map[string]string{}, payment) // no tenant, no country
		api := span("api-gateway", map[string]string{"tenant": "acme", "country": "es"}, billing)
		trees = append(trees, []*tempo.Span{api})
	}

	findings := DetectNoCoverage(trees, []string{"tenant", "country"}, 5, 0.0, time.Now())

	byService := map[string]CoverageAnomaly{}
	for _, f := range findings {
		byService[f.Service] = f
	}

	// billing-svc: sits between api-gateway and payment-svc, carries no baggage.
	b, ok := byService["billing-svc"]
	if !ok {
		t.Fatal("expected billing-svc to be flagged for zero baggage coverage")
	}
	if b.Coverage != 0.0 {
		t.Errorf("billing-svc coverage: want 0.0, got %.2f", b.Coverage)
	}
	if !b.IsMiddleware {
		t.Error("billing-svc is middleware (callee AND caller) — IsMiddleware should be true")
	}

	// payment-svc: also no baggage, but it's a leaf (no children) — not middleware.
	p, ok := byService["payment-svc"]
	if !ok {
		t.Fatal("expected payment-svc to be flagged (it has no baggage)")
	}
	if p.IsMiddleware {
		t.Error("payment-svc is a leaf — IsMiddleware should be false")
	}

	// api-gateway: has baggage — should NOT be flagged.
	if _, flagged := byService["api-gateway"]; flagged {
		t.Error("api-gateway carries baggage and should not be flagged")
	}
}

func TestDetectNoCoverage_partialCoverage(t *testing.T) {
	// billing-svc carries tenant but not country — 50% key coverage per span.
	// DetectNoCoverage counts per-span (has ANY key), so coverage = 100% here
	// (every span has at least one key). Not flagged at maxCoverage=0.0.
	trees := [][]*tempo.Span{}
	for i := 0; i < 10; i++ {
		child := span("billing-svc", map[string]string{"tenant": "acme"}) // has tenant, no country
		root := span("api-gateway", map[string]string{"tenant": "acme", "country": "es"}, child)
		trees = append(trees, []*tempo.Span{root})
	}

	findings := DetectNoCoverage(trees, []string{"tenant", "country"}, 5, 0.0, time.Now())
	for _, f := range findings {
		if f.Service == "billing-svc" {
			t.Errorf("billing-svc has tenant on every span — should not be flagged at maxCoverage=0.0, got %+v", f)
		}
	}
}

func TestDetectNoCoverage_belowMinSpans(t *testing.T) {
	// Only 3 spans — below minSpans=5, should be ignored.
	trees := [][]*tempo.Span{}
	for i := 0; i < 3; i++ {
		child := span("rare-svc", map[string]string{})
		root := span("caller", map[string]string{"tenant": "acme"}, child)
		trees = append(trees, []*tempo.Span{root})
	}

	findings := DetectNoCoverage(trees, []string{"tenant"}, 5, 0.0, time.Now())
	for _, f := range findings {
		if f.Service == "rare-svc" {
			t.Errorf("rare-svc has fewer than minSpans — should be ignored, got %+v", f)
		}
	}
}

func TestDetectNoCoverage_emptyBaggageKeys(t *testing.T) {
	// No baggage keys configured — nothing to check, should return nil.
	trees := [][]*tempo.Span{
		{span("svc", map[string]string{})},
	}
	findings := DetectNoCoverage(trees, nil, 1, 0.0, time.Now())
	if findings != nil {
		t.Errorf("expected nil with no baggage keys, got %+v", findings)
	}
}

func TestDetectNoCoverage_sortedWorstFirst(t *testing.T) {
	// svc-a: 0% coverage, svc-b: 50% coverage — svc-a should appear first.
	trees := [][]*tempo.Span{}
	for i := 0; i < 10; i++ {
		a := span("svc-a", map[string]string{}) // always missing
		b := span("svc-b", map[string]string{})
		if i < 5 {
			b.Attrs["tenant"] = "acme" // half have it
		}
		root := span("entry", map[string]string{"tenant": "acme"}, a, b)
		trees = append(trees, []*tempo.Span{root})
	}

	findings := DetectNoCoverage(trees, []string{"tenant"}, 5, 1.0, time.Now())
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	if findings[0].Service != "svc-a" {
		t.Errorf("expected svc-a (0%% coverage) first, got %s", findings[0].Service)
	}
}
