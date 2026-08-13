package analysis

import (
	"testing"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

// makeTree builds a simple root→child1→child2 chain.
func makeTree(rootService, child1, child2 string) []*tempo.Span {
	root := &tempo.Span{SpanID: "s1", Service: rootService}
	c1 := &tempo.Span{SpanID: "s2", ParentSpanID: "s1", Service: child1}
	c2 := &tempo.Span{SpanID: "s3", ParentSpanID: "s2", Service: child2}
	c1.Children = []*tempo.Span{c2}
	root.Children = []*tempo.Span{c1}
	return []*tempo.Span{root}
}

func TestDetectRootAnomalies_noAnomaly(t *testing.T) {
	var trees [][]*tempo.Span
	for i := 0; i < 100; i++ {
		trees = append(trees, makeTree("frontend", "api", "billing"))
	}
	findings := DetectRootAnomalies(trees, 50, 0.001, time.Now())
	for _, f := range findings {
		if f.Service == "billing" {
			t.Errorf("billing should not be flagged, got %+v", f)
		}
	}
}

// TestDetectRootAnomalies_receivingDrop: billing appears as a leaf orphan root —
// its caller dropped traceparent so billing never received it.
// Signature: AsRoot > 0, RootWithChildren == 0, Kind == "receiving_drop".
func TestDetectRootAnomalies_receivingDrop(t *testing.T) {
	var trees [][]*tempo.Span
	for i := 0; i < 100; i++ {
		trees = append(trees, makeTree("frontend", "api", "billing"))
	}
	// billing starts orphan root traces with no children.
	for i := 0; i < 5; i++ {
		orphan := &tempo.Span{SpanID: "ox", Service: "billing"} // no Children
		trees = append(trees, []*tempo.Span{orphan})
	}

	findings := DetectRootAnomalies(trees, 50, 0.001, time.Now())
	var f *RootAnomaly
	for i := range findings {
		if findings[i].Service == "billing" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatal("expected billing to be flagged")
	}
	if f.Kind != "receiving_drop" {
		t.Errorf("expected kind=receiving_drop, got %q", f.Kind)
	}
	if f.RootWithChildren != 0 {
		t.Errorf("expected RootWithChildren=0, got %d", f.RootWithChildren)
	}
}

// TestDetectRootAnomalies_orphanCreator: api-gateway appears as a root WITH children —
// it received the traceparent correctly in complete traces but creates a fresh
// traceparent when making outgoing calls in other traces.
// Signature: AsRoot > 0, RootWithChildren == AsRoot, Kind == "orphan_creator".
func TestDetectRootAnomalies_orphanCreator(t *testing.T) {
	var trees [][]*tempo.Span

	// 100 complete traces: frontend → api-gateway → billing.
	// api-gateway is a callee here.
	for i := 0; i < 100; i++ {
		trees = append(trees, makeTree("frontend", "api-gateway", "billing"))
	}

	// 8 traces where api-gateway created a new traceparent for its outgoing calls.
	// It appears as root AND has children (billing is called under the new context).
	for i := 0; i < 8; i++ {
		gw := &tempo.Span{SpanID: "gw", Service: "api-gateway"}
		child := &tempo.Span{SpanID: "b", ParentSpanID: "gw", Service: "billing"}
		gw.Children = []*tempo.Span{child}
		trees = append(trees, []*tempo.Span{gw})
	}

	findings := DetectRootAnomalies(trees, 50, 0.001, time.Now())
	var f *RootAnomaly
	for i := range findings {
		if findings[i].Service == "api-gateway" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatal("expected api-gateway to be flagged")
	}
	if f.Kind != "orphan_creator" {
		t.Errorf("expected kind=orphan_creator, got %q", f.Kind)
	}
	if f.RootWithChildren != 8 {
		t.Errorf("expected RootWithChildren=8, got %d", f.RootWithChildren)
	}
	if f.AsRoot != 8 {
		t.Errorf("expected AsRoot=8, got %d", f.AsRoot)
	}
}

// TestDetectRootAnomalies_mixed: a service shows both patterns —
// sometimes it's a leaf orphan (caller dropped traceparent) and sometimes
// it's a root with children (it created a fresh context itself).
func TestDetectRootAnomalies_mixed(t *testing.T) {
	var trees [][]*tempo.Span
	for i := 0; i < 100; i++ {
		trees = append(trees, makeTree("frontend", "api-gateway", "billing"))
	}
	// Leaf orphan roots (receiving_drop pattern).
	for i := 0; i < 3; i++ {
		orphan := &tempo.Span{SpanID: "leaf", Service: "api-gateway"}
		trees = append(trees, []*tempo.Span{orphan})
	}
	// Roots with children (orphan_creator pattern).
	for i := 0; i < 4; i++ {
		gw := &tempo.Span{SpanID: "gw", Service: "api-gateway"}
		child := &tempo.Span{SpanID: "b", ParentSpanID: "gw", Service: "billing"}
		gw.Children = []*tempo.Span{child}
		trees = append(trees, []*tempo.Span{gw})
	}

	findings := DetectRootAnomalies(trees, 50, 0.001, time.Now())
	var f *RootAnomaly
	for i := range findings {
		if findings[i].Service == "api-gateway" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatal("expected api-gateway to be flagged")
	}
	if f.Kind != "mixed" {
		t.Errorf("expected kind=mixed, got %q", f.Kind)
	}
	if f.RootWithChildren != 4 {
		t.Errorf("expected RootWithChildren=4, got %d", f.RootWithChildren)
	}
	if f.AsRoot != 7 {
		t.Errorf("expected AsRoot=7 (3 leaf + 4 with children), got %d", f.AsRoot)
	}
}
