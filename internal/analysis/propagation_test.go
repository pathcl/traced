package analysis

import (
	"testing"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

func TestDetectBaggagePropagation_noHeaderAttr(t *testing.T) {
	// Spans carry custom attributes but no baggage header attribute —
	// instrumentation is not capturing the header. Should return nil.
	parent := makeSpanWithAttrs("s1", "", "api", map[string]string{"tenant": "acme"})
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{"tenant": "acme"})
	parent.Children = []*tempo.Span{child}

	drops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "", time.Now())
	if drops != nil {
		t.Errorf("expected nil when no baggage header attr found, got %+v", drops)
	}
}

func TestDetectBaggagePropagation_noDrop(t *testing.T) {
	// Both parent and child have http.request.header.baggage → no drop.
	parent := makeSpanWithAttrs("s1", "", "api",
		map[string]string{"http.request.header.baggage": "tenant=acme,country=es"})
	child := makeSpanWithAttrs("s2", "s1", "billing",
		map[string]string{"http.request.header.baggage": "tenant=acme,country=es"})
	parent.Children = []*tempo.Span{child}

	drops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "", time.Now())
	if len(drops) != 0 {
		t.Errorf("expected no drops, got %+v", drops)
	}
}

func TestDetectBaggagePropagation_drop(t *testing.T) {
	// Parent has the baggage header attr; child does not → api dropped it.
	parent := makeSpanWithAttrs("s1", "", "api",
		map[string]string{"http.request.header.baggage": "tenant=acme"})
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{})
	parent.Children = []*tempo.Span{child}

	drops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "", time.Now())
	if len(drops) != 1 {
		t.Fatalf("expected 1 drop, got %d", len(drops))
	}
	d := drops[0]
	if d.Caller != "api" || d.Callee != "billing" {
		t.Errorf("unexpected caller/callee: %s→%s", d.Caller, d.Callee)
	}
	if d.HeaderAttr != "http.request.header.baggage" {
		t.Errorf("unexpected header attr: %q", d.HeaderAttr)
	}
	if d.DropRate != 1.0 {
		t.Errorf("expected drop rate 1.0, got %.2f", d.DropRate)
	}
}

func TestDetectBaggagePropagation_partialDrop(t *testing.T) {
	// 10 calls: 7 forward the header, 3 drop it.
	var trees [][]*tempo.Span
	for i := 0; i < 7; i++ {
		p := makeSpanWithAttrs("s1", "", "api",
			map[string]string{"http.request.header.baggage": "tenant=acme"})
		c := makeSpanWithAttrs("s2", "s1", "billing",
			map[string]string{"http.request.header.baggage": "tenant=acme"})
		p.Children = []*tempo.Span{c}
		trees = append(trees, []*tempo.Span{p})
	}
	for i := 0; i < 3; i++ {
		p := makeSpanWithAttrs("s1", "", "api",
			map[string]string{"http.request.header.baggage": "tenant=acme"})
		c := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{}) // dropped
		p.Children = []*tempo.Span{c}
		trees = append(trees, []*tempo.Span{p})
	}

	drops := DetectBaggagePropagation(trees, "", time.Now())
	if len(drops) != 1 {
		t.Fatalf("expected 1 drop finding, got %d", len(drops))
	}
	if drops[0].DropRate < 0.29 || drops[0].DropRate > 0.31 {
		t.Errorf("expected ~0.30 drop rate, got %.4f", drops[0].DropRate)
	}
	if drops[0].Dropped != 3 || drops[0].Total != 10 {
		t.Errorf("expected 3/10, got %d/%d", drops[0].Dropped, drops[0].Total)
	}
}

func TestDetectBaggagePropagation_plainBaggageKey(t *testing.T) {
	// Some SDKs capture it as just "baggage" (no prefix).
	parent := makeSpanWithAttrs("s1", "", "api",
		map[string]string{"baggage": "tenant=acme"})
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{})
	parent.Children = []*tempo.Span{child}

	drops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "", time.Now())
	if len(drops) != 1 {
		t.Fatalf("expected 1 drop for plain 'baggage' attr, got %d", len(drops))
	}
	if drops[0].HeaderAttr != "baggage" {
		t.Errorf("expected header attr 'baggage', got %q", drops[0].HeaderAttr)
	}
}

func TestDetectBaggagePropagation_configuredKey(t *testing.T) {
	// User configures "ind.baggage.cj" — the auto-detect pattern would not match this.
	// With an explicit key, we should detect the drop correctly.
	parent := makeSpanWithAttrs("s1", "", "api",
		map[string]string{"ind.baggage.cj": "tenant=acme,country=es"})
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{})
	parent.Children = []*tempo.Span{child}

	// Without the configured key, auto-detect should return nil.
	noDrops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "", time.Now())
	if noDrops != nil {
		t.Errorf("auto-detect should miss ind.baggage.cj, got %+v", noDrops)
	}

	// With the configured key, the drop is found.
	drops := DetectBaggagePropagation([][]*tempo.Span{{parent}}, "ind.baggage.cj", time.Now())
	if len(drops) != 1 {
		t.Fatalf("expected 1 drop with configured key, got %d", len(drops))
	}
	if drops[0].HeaderAttr != "ind.baggage.cj" {
		t.Errorf("expected header attr 'ind.baggage.cj', got %q", drops[0].HeaderAttr)
	}
}
