package analysis

import (
	"testing"

	"github.com/pathcl/traced/internal/tempo"
)

func TestDiscoverSpanAttributes_findsCustomAttrs(t *testing.T) {
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs: map[string]string{
			"tenant":      "acme",
			"country":     "es",
			"http.method": "GET",     // OTel semantic — excluded
			"db.system":   "postgres", // OTel semantic — excluded
		},
	}
	keys := DiscoverSpanAttributes([][]*tempo.Span{{root}})
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}
	if !found["tenant"] || !found["country"] {
		t.Errorf("expected tenant and country, got %v", keys)
	}
	if found["http.method"] || found["db.system"] {
		t.Error("OTel semantic attributes should be excluded")
	}
}

func TestDiscoverSpanAttributes_excludesBaggageHeaderAttr(t *testing.T) {
	// The baggage header attribute (http.request.header.baggage) is a
	// propagation mechanism, not an application span attribute — exclude it.
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs: map[string]string{
			"http.request.header.baggage": "tenant=acme,country=es",
			"tenant":                      "acme",
		},
	}
	keys := DiscoverSpanAttributes([][]*tempo.Span{{root}})
	for _, k := range keys {
		if k == "http.request.header.baggage" || k == "baggage" {
			t.Errorf("baggage header attr %q should not be discovered as a span attribute", k)
		}
	}
}

func TestDiscoverSpanAttributes_deduplicatesAcrossRoots(t *testing.T) {
	trees := [][]*tempo.Span{
		{{SpanID: "r1", Service: "a", Attrs: map[string]string{"tenant": "acme", "region": "eu"}}},
		{{SpanID: "r2", Service: "b", Attrs: map[string]string{"tenant": "globex", "env": "prod"}}},
	}
	keys := DiscoverSpanAttributes(trees)
	counts := map[string]int{}
	for _, k := range keys {
		counts[k]++
	}
	for k, n := range counts {
		if n > 1 {
			t.Errorf("key %q appears %d times, want 1", k, n)
		}
	}
	for _, want := range []string{"tenant", "region", "env"} {
		if counts[want] == 0 {
			t.Errorf("expected %q to be discovered", want)
		}
	}
}

func TestDiscoverSpanAttributes_ignoresChildSpanAttrs(t *testing.T) {
	// Discovery only looks at root spans — child-only attributes are ignored.
	root := &tempo.Span{SpanID: "r1", Service: "api", Attrs: map[string]string{"tenant": "x"}}
	child := &tempo.Span{SpanID: "c1", ParentSpanID: "r1", Service: "db",
		Attrs: map[string]string{"internal_id": "42"}}
	root.Children = []*tempo.Span{child}

	keys := DiscoverSpanAttributes([][]*tempo.Span{{root}})
	for _, k := range keys {
		if k == "internal_id" {
			t.Error("internal_id is on a child span only and should not be discovered")
		}
	}
}

func TestDiscoverSpanAttributes_emptyWhenNoCustomAttrs(t *testing.T) {
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs:   map[string]string{"http.method": "GET", "http.status_code": "200"},
	}
	keys := DiscoverSpanAttributes([][]*tempo.Span{{root}})
	if len(keys) != 0 {
		t.Errorf("expected no keys, got %v", keys)
	}
}

func TestDiscoverSpanAttributes_isSorted(t *testing.T) {
	root := &tempo.Span{
		Attrs: map[string]string{"zebra": "1", "alpha": "2", "middle": "3"},
	}
	keys := DiscoverSpanAttributes([][]*tempo.Span{{root}})
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Errorf("keys not sorted: %v", keys)
		}
	}
}
