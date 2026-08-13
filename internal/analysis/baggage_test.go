package analysis

import (
	"testing"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

func makeSpanWithAttrs(spanID, parentID, service string, attrs map[string]string) *tempo.Span {
	return &tempo.Span{
		SpanID:       spanID,
		ParentSpanID: parentID,
		Service:      service,
		Attrs:        attrs,
	}
}

func TestDetectSpanAttributeDrops_noDrop(t *testing.T) {
	parent := makeSpanWithAttrs("s1", "", "api", map[string]string{"tenant": "acme"})
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{"tenant": "acme"})
	parent.Children = []*tempo.Span{child}

	trees := [][]*tempo.Span{{parent}}
	findings := DetectSpanAttributeDrops(trees, []string{"tenant"}, time.Now())
	if len(findings) != 0 {
		t.Errorf("expected no drops, got %+v", findings)
	}
}

func TestDetectSpanAttributeDrops_drop(t *testing.T) {
	parent := makeSpanWithAttrs("s1", "", "api", map[string]string{"tenant": "acme"})
	// billing drops tenant.
	child := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{})
	parent.Children = []*tempo.Span{child}

	trees := [][]*tempo.Span{{parent}}
	findings := DetectSpanAttributeDrops(trees, []string{"tenant"}, time.Now())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Caller != "api" || f.Callee != "billing" || f.Attribute != "tenant" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.DropRate != 1.0 {
		t.Errorf("expected drop rate 1.0, got %.2f", f.DropRate)
	}
}

func TestDetectSpanAttributeDrops_partialDrop(t *testing.T) {
	// 10 calls api→billing, 3 of them drop tenant.
	var trees [][]*tempo.Span
	for i := 0; i < 7; i++ {
		p := makeSpanWithAttrs("s1", "", "api", map[string]string{"tenant": "acme"})
		c := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{"tenant": "acme"})
		p.Children = []*tempo.Span{c}
		trees = append(trees, []*tempo.Span{p})
	}
	for i := 0; i < 3; i++ {
		p := makeSpanWithAttrs("s1", "", "api", map[string]string{"tenant": "acme"})
		c := makeSpanWithAttrs("s2", "s1", "billing", map[string]string{}) // drop
		p.Children = []*tempo.Span{c}
		trees = append(trees, []*tempo.Span{p})
	}
	findings := DetectSpanAttributeDrops(trees, []string{"tenant"}, time.Now())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].DropRate < 0.29 || findings[0].DropRate > 0.31 {
		t.Errorf("expected drop rate ~0.3, got %.4f", findings[0].DropRate)
	}
}
