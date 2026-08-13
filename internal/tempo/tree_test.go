package tempo

import (
	"testing"
)

func TestBuildTree_singleRoot(t *testing.T) {
	raw := []RawSpan{
		{TraceID: "t1", SpanID: "s1", ParentSpanID: "", Service: "frontend"},
		{TraceID: "t1", SpanID: "s2", ParentSpanID: "s1", Service: "api"},
		{TraceID: "t1", SpanID: "s3", ParentSpanID: "s2", Service: "billing"},
	}
	roots := BuildTree(raw)
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	if roots[0].Service != "frontend" {
		t.Errorf("expected root service=frontend, got %s", roots[0].Service)
	}
	if len(roots[0].Children) != 1 || roots[0].Children[0].Service != "api" {
		t.Errorf("expected frontend→api child")
	}
	if len(roots[0].Children[0].Children) != 1 || roots[0].Children[0].Children[0].Service != "billing" {
		t.Errorf("expected api→billing grandchild")
	}
}

func TestBuildTree_orphanRoot(t *testing.T) {
	// billing's parent span is missing — simulates a dropped traceparent.
	raw := []RawSpan{
		{TraceID: "t2", SpanID: "s1", ParentSpanID: "", Service: "frontend"},
		// s2 (api) span is absent — billing arrives with dangling parentSpanID.
		{TraceID: "t2", SpanID: "s3", ParentSpanID: "s2-missing", Service: "billing"},
	}
	roots := BuildTree(raw)
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots (frontend + orphaned billing), got %d", len(roots))
	}
	services := map[string]bool{}
	for _, r := range roots {
		services[r.Service] = true
	}
	if !services["frontend"] || !services["billing"] {
		t.Errorf("expected both frontend and billing as roots, got %v", services)
	}
}

func TestWalk_visitsAllSpans(t *testing.T) {
	raw := []RawSpan{
		{TraceID: "t3", SpanID: "s1", Service: "a"},
		{TraceID: "t3", SpanID: "s2", ParentSpanID: "s1", Service: "b"},
		{TraceID: "t3", SpanID: "s3", ParentSpanID: "s1", Service: "c"},
	}
	roots := BuildTree(raw)
	visited := map[string]bool{}
	Walk(roots, func(_, s *Span) { visited[s.Service] = true })
	for _, svc := range []string{"a", "b", "c"} {
		if !visited[svc] {
			t.Errorf("Walk did not visit service %s", svc)
		}
	}
}
