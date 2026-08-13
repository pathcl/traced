package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/pathcl/traced/internal/analysis"
	"github.com/pathcl/traced/internal/tempo"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("")
	if err != nil {
		t.Fatalf("Open in-memory store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpen_createsSchema(t *testing.T) {
	s := openTestStore(t)
	for _, table := range []string{"ticks", "spans", "findings"} {
		var name string
		err := s.db.QueryRowContext(context.Background(),
			`SELECT table_name FROM information_schema.tables WHERE table_name = ?`, table).
			Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestSaveTick_roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	meta := TickMeta{
		TickID:        "tick-1",
		WindowStart:   now.Add(-10 * time.Minute),
		WindowEnd:     now,
		TracesFetched: 47,
		TreesBuilt:    45,
	}
	if err := s.SaveTick(ctx, meta); err != nil {
		t.Fatalf("SaveTick: %v", err)
	}

	var tickID string
	var fetched, built int
	err := s.db.QueryRowContext(ctx,
		`SELECT tick_id, traces_fetched, trees_built FROM ticks WHERE tick_id = ?`, "tick-1").
		Scan(&tickID, &fetched, &built)
	if err != nil {
		t.Fatalf("query tick: %v", err)
	}
	if tickID != "tick-1" {
		t.Errorf("tick_id: want tick-1, got %q", tickID)
	}
	if fetched != 47 {
		t.Errorf("traces_fetched: want 47, got %d", fetched)
	}
	if built != 45 {
		t.Errorf("trees_built: want 45, got %d", built)
	}
}

func TestSaveSpans_storesAllAttrs(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Build a simple two-span tree: frontend → billing.
	root := &tempo.Span{
		TraceID: "trace-1", SpanID: "s1", Service: "frontend", Name: "GET /",
		Attrs: map[string]string{"tenant": "acme", "country": "es", "http.method": "GET"},
	}
	child := &tempo.Span{
		TraceID: "trace-1", SpanID: "s2", ParentSpanID: "s1",
		Service: "billing", Name: "charge",
		Attrs: map[string]string{"tenant": "acme"},
	}
	root.Children = []*tempo.Span{child}
	trees := [][]*tempo.Span{{root}}

	if err := s.SaveSpans(ctx, "tick-1", trees); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	// Two spans should be persisted.
	var count int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM spans WHERE tick_id = 'tick-1'`).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 spans, got %d", count)
	}

	// Root flag is correct.
	var isRoot bool
	s.db.QueryRowContext(ctx, `SELECT is_root FROM spans WHERE span_id = 's1'`).Scan(&isRoot)
	if !isRoot {
		t.Error("span s1 (frontend root) should have is_root=true")
	}
	s.db.QueryRowContext(ctx, `SELECT is_root FROM spans WHERE span_id = 's2'`).Scan(&isRoot)
	if isRoot {
		t.Error("span s2 (billing child) should have is_root=false")
	}

	// Full attrs JSON is queryable via json_extract.
	var tenant string
	err := s.db.QueryRowContext(ctx,
		`SELECT json_extract_string(attrs, '$.tenant') FROM spans WHERE span_id = 's1'`).
		Scan(&tenant)
	if err != nil {
		t.Fatalf("json_extract_string: %v", err)
	}
	if tenant != "acme" {
		t.Errorf("expected tenant=acme, got %q", tenant)
	}

	// All attribute keys are stored — including OTel semantic ones.
	// For keys containing dots, use the arrow operator (->>) instead of
	// json_extract_string with JSONPath: $.http.method is parsed as nested
	// objects http → method, not as the literal key "http.method".
	var httpMethod string
	s.db.QueryRowContext(ctx,
		`SELECT attrs->>'http.method' FROM spans WHERE span_id = 's1'`).
		Scan(&httpMethod)
	if httpMethod != "GET" {
		t.Errorf("expected http.method=GET, got %q", httpMethod)
	}
}

func TestSaveFindings_allThreeTypes(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	roots := []analysis.RootAnomaly{
		{Service: "billing", AsCallee: 100, AsRoot: 5, DropRate: 0.05, Window: now},
	}
	drops := []analysis.SpanAttributeDrop{
		{Caller: "api", Callee: "billing", Attribute: "tenant", DropRate: 0.3, Dropped: 30, Total: 100, Window: now},
	}
	gaps := []analysis.LabelGap{
		{Caller: "frontend", Callee: "api", Attribute: "country", InTrace: true, InMetric: false, Window: now},
	}

	if err := s.SaveFindings(ctx, "tick-1", roots, drops, gaps); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	// One finding per type.
	rows, err := s.db.QueryContext(ctx, `SELECT kind, service, caller, callee, attribute FROM findings ORDER BY kind`)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()

	type row struct{ kind, service, caller, callee, attribute string }
	var got []row
	for rows.Next() {
		var r row
		var svc, caller, callee, attr sql.NullString
		rows.Scan(&r.kind, &svc, &caller, &callee, &attr)
		r.service = svc.String
		r.caller = caller.String
		r.callee = callee.String
		r.attribute = attr.String
		got = append(got, r)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}

	byKind := map[string]row{}
	for _, r := range got {
		byKind[r.kind] = r
	}

	if byKind["root_anomaly"].service != "billing" {
		t.Errorf("root_anomaly: expected service=billing, got %q", byKind["root_anomaly"].service)
	}
	if byKind["baggage_drop"].caller != "api" || byKind["baggage_drop"].attribute != "tenant" {
		t.Errorf("baggage_drop: unexpected values %+v", byKind["baggage_drop"])
	}
	if byKind["label_gap"].caller != "frontend" || byKind["label_gap"].attribute != "country" {
		t.Errorf("label_gap: unexpected values %+v", byKind["label_gap"])
	}
}

func TestQueryAttributeDrops_detectsDrops(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Build three traces:
	//   trace-ok:   api(tenant=acme) → billing(tenant=acme)     — no drop
	//   trace-drop: api(tenant=acme) → billing(tenant="")        — tenant dropped
	//   trace-otel: api(http.method=GET) → billing(http.method="") — OTel attr, should be filterable

	ok := func(traceID, parentID, svc string, attrs map[string]string) *tempo.Span {
		return &tempo.Span{TraceID: traceID, SpanID: svc + "-" + traceID,
			ParentSpanID: parentID, Service: svc, Attrs: attrs}
	}
	link := func(parent, child *tempo.Span) *tempo.Span {
		parent.Children = append(parent.Children, child)
		return parent
	}

	trees := [][]*tempo.Span{
		// 7 clean calls: tenant propagates correctly
		func() []*tempo.Span {
			var roots []*tempo.Span
			for i := 0; i < 7; i++ {
				id := fmt.Sprintf("ok-%d", i)
				p := ok(id, "", "api", map[string]string{"tenant": "acme"})
				c := ok(id, "api-"+id, "billing", map[string]string{"tenant": "acme"})
				link(p, c)
				roots = append(roots, p)
			}
			return roots
		}(),
		// 3 calls where billing drops tenant
		func() []*tempo.Span {
			var roots []*tempo.Span
			for i := 0; i < 3; i++ {
				id := fmt.Sprintf("drop-%d", i)
				p := ok(id, "", "api", map[string]string{"tenant": "acme"})
				c := ok(id, "api-"+id, "billing", map[string]string{})
				link(p, c)
				roots = append(roots, p)
			}
			return roots
		}(),
		// 5 calls where an OTel attr differs (legitimate — not baggage)
		func() []*tempo.Span {
			var roots []*tempo.Span
			for i := 0; i < 5; i++ {
				id := fmt.Sprintf("otel-%d", i)
				p := ok(id, "", "api", map[string]string{"http.method": "GET", "tenant": "acme"})
				c := ok(id, "api-"+id, "billing", map[string]string{"tenant": "acme"}) // http.method absent — normal
				link(p, c)
				roots = append(roots, p)
			}
			return roots
		}(),
	}

	// Flatten into one tree slice the store expects.
	var allTrees [][]*tempo.Span
	for _, group := range trees {
		for _, root := range group {
			allTrees = append(allTrees, []*tempo.Span{root})
		}
	}

	if err := s.SaveSpans(ctx, "tick-1", allTrees); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	// Without OTel filter: should see both tenant and http.method drops.
	all, err := s.QueryAttributeDrops(ctx, false)
	if err != nil {
		t.Fatalf("QueryAttributeDrops(otelFilter=false): %v", err)
	}
	byKey := map[string]AttributeDrop{}
	for _, d := range all {
		if d.Caller == "api" && d.Callee == "billing" {
			byKey[d.DroppedKey] = d
		}
	}
	if _, ok := byKey["tenant"]; !ok {
		t.Errorf("expected tenant drop in unfiltered results, got: %+v", all)
	}
	if _, ok := byKey["http.method"]; !ok {
		t.Errorf("expected http.method in unfiltered results, got: %+v", all)
	}
	if byKey["tenant"].TimesDropped != 3 {
		t.Errorf("tenant: want 3 drops, got %d", byKey["tenant"].TimesDropped)
	}
	if byKey["tenant"].TotalCalls != 15 {
		t.Errorf("tenant: want 15 total calls (7+3+5), got %d", byKey["tenant"].TotalCalls)
	}

	// With OTel filter: http.method should disappear, tenant should remain.
	filtered, err := s.QueryAttributeDrops(ctx, true)
	if err != nil {
		t.Fatalf("QueryAttributeDrops(otelFilter=true): %v", err)
	}
	byKeyFiltered := map[string]AttributeDrop{}
	for _, d := range filtered {
		if d.Caller == "api" && d.Callee == "billing" {
			byKeyFiltered[d.DroppedKey] = d
		}
	}
	if _, ok := byKeyFiltered["http.method"]; ok {
		t.Error("http.method should be filtered out as an OTel semantic attribute")
	}
	if _, ok := byKeyFiltered["tenant"]; !ok {
		t.Error("tenant should remain after OTel filter")
	}
}

func TestQueryAttributeDrops_noDrops(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	parent := &tempo.Span{
		TraceID: "t1", SpanID: "s1", Service: "api",
		Attrs: map[string]string{"tenant": "acme"},
	}
	child := &tempo.Span{
		TraceID: "t1", SpanID: "s2", ParentSpanID: "s1", Service: "billing",
		Attrs: map[string]string{"tenant": "acme"},
	}
	parent.Children = []*tempo.Span{child}

	if err := s.SaveSpans(ctx, "tick-1", [][]*tempo.Span{{parent}}); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	drops, err := s.QueryAttributeDrops(ctx, true)
	if err != nil {
		t.Fatalf("QueryAttributeDrops: %v", err)
	}
	if len(drops) != 0 {
		t.Errorf("expected no drops, got: %+v", drops)
	}
}

func TestSaveSpans_baggageQueryableWithoutPriorKnowledge(t *testing.T) {
	// This test demonstrates the key value of storing full attrs as JSON:
	// you can discover which attribute keys exist and query them without
	// knowing the schema upfront.
	s := openTestStore(t)
	ctx := context.Background()

	trees := [][]*tempo.Span{{
		{
			TraceID: "t1", SpanID: "s1", Service: "api",
			Attrs: map[string]string{"tenant": "acme", "region": "eu-west-1"},
		},
		{
			TraceID: "t1", SpanID: "s2", Service: "api",
			Attrs: map[string]string{"tenant": "globex"},
		},
	}}
	if err := s.SaveSpans(ctx, "tick-1", trees); err != nil {
		t.Fatalf("SaveSpans: %v", err)
	}

	// Discover all distinct attribute keys across all stored spans.
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT unnest(json_keys(attrs)) AS k
		FROM spans
		ORDER BY k`)
	if err != nil {
		t.Fatalf("discover attrs query: %v", err)
	}
	defer rows.Close()

	keys := map[string]bool{}
	for rows.Next() {
		var k string
		rows.Scan(&k)
		keys[k] = true
	}

	if !keys["tenant"] {
		t.Error("expected 'tenant' key to be discoverable from stored attrs")
	}
	if !keys["region"] {
		t.Error("expected 'region' key to be discoverable from stored attrs")
	}
}
