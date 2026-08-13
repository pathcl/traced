package analysis

import (
	"testing"
	"time"

	"github.com/pathcl/traced/internal/mimir"
	"github.com/pathcl/traced/internal/tempo"
)

// buildTree creates a two-span trace (parent→child) with given services and attrs.
func buildTree(callerService, calleeService string, callerAttrs, calleeAttrs map[string]string) []*tempo.Span {
	parent := &tempo.Span{SpanID: "p", Service: callerService, Attrs: callerAttrs}
	child := &tempo.Span{SpanID: "c", ParentSpanID: "p", Service: calleeService, Attrs: calleeAttrs}
	parent.Children = []*tempo.Span{child}
	return []*tempo.Span{parent}
}

func TestDetectLabelGaps_noGap(t *testing.T) {
	// Trace has tenant; metric also has tenant → no gap.
	trees := [][]*tempo.Span{
		buildTree("frontend", "api",
			map[string]string{"tenant": "acme"},
			map[string]string{"tenant": "acme"},
		),
	}
	metricSamples := []mimir.Sample{
		{Labels: map[string]string{"client": "frontend", "server": "api", "tenant": "acme"}, Value: 10},
	}
	findings := DetectLabelGaps(trees, metricSamples, []string{"tenant"}, time.Now())
	for _, f := range findings {
		if f.Caller == "frontend" && f.Callee == "api" && f.Attribute == "tenant" {
			t.Errorf("unexpected gap finding: %+v", f)
		}
	}
}

func TestDetectLabelGaps_attrInTraceNotInMetric(t *testing.T) {
	// Span has tenant=acme but the metric series for that edge has no tenant label.
	// This means the OTel connector dimensions config is missing "tenant".
	trees := [][]*tempo.Span{
		buildTree("frontend", "billing",
			map[string]string{"tenant": "acme"},
			map[string]string{"tenant": "acme"},
		),
	}
	metricSamples := []mimir.Sample{
		// metric exists but has no tenant label
		{Labels: map[string]string{"client": "frontend", "server": "billing"}, Value: 5},
	}
	findings := DetectLabelGaps(trees, metricSamples, []string{"tenant"}, time.Now())

	var found bool
	for _, f := range findings {
		if f.Caller == "frontend" && f.Callee == "billing" && f.Attribute == "tenant" && f.InTrace && !f.InMetric {
			found = true
		}
	}
	if !found {
		t.Errorf("expected label gap finding for frontend→billing/tenant, got: %+v", findings)
	}
}

func TestDetectLabelGaps_edgeInMetricNotInTrace(t *testing.T) {
	// Metric series exists for payment→db but we never observed that edge in traces.
	// Could be stale series or a sampling gap.
	trees := [][]*tempo.Span{
		buildTree("frontend", "api",
			map[string]string{},
			map[string]string{},
		),
	}
	metricSamples := []mimir.Sample{
		{Labels: map[string]string{"client": "frontend", "server": "api"}, Value: 3},
		// This edge was never seen in our trace sample.
		{Labels: map[string]string{"client": "payment", "server": "db"}, Value: 1},
	}
	findings := DetectLabelGaps(trees, metricSamples, []string{"tenant"}, time.Now())

	var found bool
	for _, f := range findings {
		if f.Caller == "payment" && f.Callee == "db" && !f.InTrace && f.InMetric {
			found = true
		}
	}
	if !found {
		t.Errorf("expected stale-series finding for payment→db, got: %+v", findings)
	}
}

func TestDetectLabelGaps_multipleKeys(t *testing.T) {
	// Trace has both tenant and country; metric has neither.
	// Should produce two separate gap findings (one per key).
	trees := [][]*tempo.Span{
		buildTree("api", "billing",
			map[string]string{"tenant": "acme", "country": "es"},
			map[string]string{"tenant": "acme", "country": "es"},
		),
	}
	metricSamples := []mimir.Sample{
		{Labels: map[string]string{"client": "api", "server": "billing"}, Value: 99},
	}
	findings := DetectLabelGaps(trees, metricSamples, []string{"tenant", "country"}, time.Now())

	missing := map[string]bool{}
	for _, f := range findings {
		if f.Caller == "api" && f.Callee == "billing" && f.InTrace && !f.InMetric {
			missing[f.Attribute] = true
		}
	}
	for _, key := range []string{"tenant", "country"} {
		if !missing[key] {
			t.Errorf("expected label gap for attribute %q, findings: %+v", key, findings)
		}
	}
}
