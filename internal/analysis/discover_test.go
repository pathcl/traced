package analysis

import (
	"reflect"
	"testing"

	"github.com/pathcl/traced/internal/tempo"
)

// --- parseBaggageHeader ---

func TestParseBaggageHeader_basic(t *testing.T) {
	got := parseBaggageHeader("tenant=acme,country=es")
	want := []string{"tenant", "country"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseBaggageHeader_withProperties(t *testing.T) {
	// Per W3C spec, members may carry properties after semicolons.
	got := parseBaggageHeader("tenant=acme;prop=v,country=es")
	want := []string{"tenant", "country"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseBaggageHeader_withSpaces(t *testing.T) {
	got := parseBaggageHeader("  tenant = acme , country = es  ")
	want := []string{"tenant", "country"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseBaggageHeader_empty(t *testing.T) {
	if got := parseBaggageHeader(""); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// --- DiscoverFromBaggageAttr ---

func TestDiscoverFromBaggageAttr_findsHttpRequestHeaderBaggage(t *testing.T) {
	// Standard OTel HTTP instrumentation attribute name.
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "api-gateway",
		Attrs: map[string]string{
			"http.request.header.baggage": "tenant=acme,country=es",
			"http.method":                 "POST",
		},
	}
	trees := [][]*tempo.Span{{root}}

	keys := DiscoverFromBaggageAttr(trees)
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}
	if !found["tenant"] || !found["country"] {
		t.Errorf("expected tenant and country, got %v", keys)
	}
	// The baggage header attr key itself must not appear as a member.
	if found["http.request.header.baggage"] {
		t.Error("the baggage attr key should not be treated as a member name")
	}
}

func TestDiscoverFromBaggageAttr_findsOnChildSpan(t *testing.T) {
	// OTel server instrumentation captures the header on the receiving span,
	// which is a child in the overall tree — discovery must scan all spans.
	root := &tempo.Span{SpanID: "r1", Service: "frontend", Attrs: map[string]string{"env": "prod"}}
	child := &tempo.Span{
		SpanID: "c1", ParentSpanID: "r1", Service: "api-gateway",
		Attrs: map[string]string{"baggage": "tenant=acme,country=es"},
	}
	root.Children = []*tempo.Span{child}
	child.ParentSpanID = "r1"

	keys := DiscoverFromBaggageAttr([][]*tempo.Span{{root}})
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}
	if !found["tenant"] || !found["country"] {
		t.Errorf("expected tenant and country from child span, got %v", keys)
	}
}

func TestDiscoverFromBaggageAttr_returnsNilWhenNoBaggageAttr(t *testing.T) {
	root := &tempo.Span{
		SpanID: "r1", Service: "svc",
		Attrs: map[string]string{"tenant": "acme", "http.method": "GET"},
	}
	if got := DiscoverFromBaggageAttr([][]*tempo.Span{{root}}); got != nil {
		t.Errorf("expected nil when no attribute key contains 'baggage', got %v", got)
	}
}

func TestDiscoverFromBaggageAttr_deduplicatesAcrossSpans(t *testing.T) {
	mkSpan := func(id, val string) *tempo.Span {
		return &tempo.Span{SpanID: id, Service: "svc",
			Attrs: map[string]string{"http.request.header.baggage": val}}
	}
	trees := [][]*tempo.Span{
		{mkSpan("r1", "tenant=acme,country=es")},
		{mkSpan("r2", "tenant=globex,region=eu")},
	}
	keys := DiscoverFromBaggageAttr(trees)
	counts := map[string]int{}
	for _, k := range keys {
		counts[k]++
	}
	for k, n := range counts {
		if n > 1 {
			t.Errorf("key %q appears %d times, want 1", k, n)
		}
	}
	if counts["tenant"] == 0 || counts["country"] == 0 || counts["region"] == 0 {
		t.Errorf("expected tenant, country, region; got %v", keys)
	}
}

// --- DiscoverBaggageKeys strategy priority ---

func TestDiscoverBaggageKeys_prefersBaggageAttrOverRootHeuristic(t *testing.T) {
	// Root span has both a baggage header attr AND an unrelated custom key.
	// The baggage-header strategy should win and return only the parsed members.
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs: map[string]string{
			"http.request.header.baggage": "tenant=acme,country=es",
			"custom_internal_key":         "xyz", // would be picked by fallback
		},
	}
	keys := DiscoverBaggageKeys([][]*tempo.Span{{root}})
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}
	if !found["tenant"] || !found["country"] {
		t.Errorf("expected tenant and country from baggage header, got %v", keys)
	}
	if found["custom_internal_key"] {
		t.Errorf("custom_internal_key should NOT appear when baggage header attr is present")
	}
}

func TestDiscoverBaggageKeys_findsCustomAttrs(t *testing.T) {
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs: map[string]string{
			"tenant":      "acme",
			"country":     "es",
			"http.method": "GET",     // OTel semantic — should be excluded
			"db.system":   "postgres", // OTel semantic — should be excluded
		},
	}
	trees := [][]*tempo.Span{{root}}

	keys := DiscoverBaggageKeys(trees)

	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}

	if !found["tenant"] {
		t.Error("expected 'tenant' to be discovered")
	}
	if !found["country"] {
		t.Error("expected 'country' to be discovered")
	}
	if found["http.method"] {
		t.Error("http.method is an OTel semantic attribute and should be excluded")
	}
	if found["db.system"] {
		t.Error("db.system is an OTel semantic attribute and should be excluded")
	}
}

func TestDiscoverBaggageKeys_deduplicatesAcrossRoots(t *testing.T) {
	trees := [][]*tempo.Span{
		{{SpanID: "r1", Service: "a", Attrs: map[string]string{"tenant": "acme", "region": "eu"}}},
		{{SpanID: "r2", Service: "b", Attrs: map[string]string{"tenant": "globex", "env": "prod"}}},
	}

	keys := DiscoverBaggageKeys(trees)
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}

	for _, want := range []string{"tenant", "region", "env"} {
		if !found[want] {
			t.Errorf("expected %q to be discovered", want)
		}
	}
	// Each key appears once despite appearing in multiple root spans.
	counts := map[string]int{}
	for _, k := range keys {
		counts[k]++
	}
	for k, n := range counts {
		if n > 1 {
			t.Errorf("key %q appears %d times, want 1", k, n)
		}
	}
}

func TestDiscoverBaggageKeys_ignoresChildSpanAttrs(t *testing.T) {
	// A child span has 'internal_id' that should NOT be treated as baggage —
	// we only sample root spans for discovery.
	root := &tempo.Span{SpanID: "r1", Service: "api", Attrs: map[string]string{"tenant": "x"}}
	child := &tempo.Span{SpanID: "c1", ParentSpanID: "r1", Service: "db",
		Attrs: map[string]string{"internal_id": "42"}}
	root.Children = []*tempo.Span{child}

	keys := DiscoverBaggageKeys([][]*tempo.Span{{root}})
	for _, k := range keys {
		if k == "internal_id" {
			t.Error("internal_id is on a child span only and should not be discovered as baggage")
		}
	}
}

func TestDiscoverBaggageKeys_emptyWhenNoCustomAttrs(t *testing.T) {
	root := &tempo.Span{
		SpanID:  "r1",
		Service: "frontend",
		Attrs:   map[string]string{"http.method": "GET", "http.status_code": "200"},
	}
	keys := DiscoverBaggageKeys([][]*tempo.Span{{root}})
	if len(keys) != 0 {
		t.Errorf("expected no keys, got %v", keys)
	}
}

func TestDiscoverBaggageKeys_isSorted(t *testing.T) {
	root := &tempo.Span{
		Attrs: map[string]string{"zebra": "1", "alpha": "2", "middle": "3"},
	}
	keys := DiscoverBaggageKeys([][]*tempo.Span{{root}})
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Errorf("keys not sorted: %v", keys)
		}
	}
}
