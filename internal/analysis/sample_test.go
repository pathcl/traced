package analysis

import (
	"testing"

	"github.com/pathcl/traced/internal/tempo"
)

func TestSampleAttributeValues_collectsDistinct(t *testing.T) {
	mkSpan := func(attrs map[string]string) *tempo.Span {
		return &tempo.Span{SpanID: "x", Service: "svc", Attrs: attrs}
	}
	trees := [][]*tempo.Span{
		{mkSpan(map[string]string{"tenant": "acme", "country": "es"})},
		{mkSpan(map[string]string{"tenant": "globex", "country": "de"})},
		{mkSpan(map[string]string{"tenant": "acme", "country": "fr"})},
	}

	got := SampleAttributeValues(trees, []string{"tenant", "country"}, 10)

	if len(got["tenant"]) != 2 {
		t.Errorf("tenant: expected 2 distinct values, got %v", got["tenant"])
	}
	if len(got["country"]) != 3 {
		t.Errorf("country: expected 3 distinct values, got %v", got["country"])
	}
}

func TestSampleAttributeValues_respectsMaxPerKey(t *testing.T) {
	var trees [][]*tempo.Span
	for i := 0; i < 20; i++ {
		s := &tempo.Span{Attrs: map[string]string{"tenant": string(rune('a' + i))}}
		trees = append(trees, []*tempo.Span{s})
	}

	got := SampleAttributeValues(trees, []string{"tenant"}, 5)
	if len(got["tenant"]) > 5 {
		t.Errorf("expected at most 5 values, got %d: %v", len(got["tenant"]), got["tenant"])
	}
}

func TestSampleAttributeValues_ignoresMissingKeys(t *testing.T) {
	s := &tempo.Span{Attrs: map[string]string{"tenant": "acme"}}
	got := SampleAttributeValues([][]*tempo.Span{{s}}, []string{"tenant", "country"}, 10)

	if len(got["tenant"]) != 1 {
		t.Errorf("expected tenant=acme, got %v", got["tenant"])
	}
	if _, ok := got["country"]; ok {
		t.Errorf("country has no values — should be absent from result, got %v", got["country"])
	}
}

func TestSampleAttributeValues_emptyKeysReturnsNil(t *testing.T) {
	s := &tempo.Span{Attrs: map[string]string{"tenant": "acme"}}
	if got := SampleAttributeValues([][]*tempo.Span{{s}}, nil, 10); got != nil {
		t.Errorf("expected nil for empty keys, got %v", got)
	}
}

func TestSampleAttributeValues_isSorted(t *testing.T) {
	trees := [][]*tempo.Span{
		{{Attrs: map[string]string{"tenant": "zebra"}}},
		{{Attrs: map[string]string{"tenant": "alpha"}}},
		{{Attrs: map[string]string{"tenant": "middle"}}},
	}
	got := SampleAttributeValues(trees, []string{"tenant"}, 10)
	vals := got["tenant"]
	for i := 1; i < len(vals); i++ {
		if vals[i] < vals[i-1] {
			t.Errorf("values not sorted: %v", vals)
		}
	}
}
