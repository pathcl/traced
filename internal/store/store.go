package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/pathcl/traced/internal/analysis"
	"github.com/pathcl/traced/internal/tempo"
)

// Store persists ticks, raw spans, and analysis findings to DuckDB.
// A single Store is safe for sequential use within one daemon tick;
// DuckDB has single-writer semantics.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) a DuckDB database at path.
// Pass an empty string for an in-memory database (useful in tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// TickMeta carries per-tick metadata saved before analysis runs.
type TickMeta struct {
	TickID        string
	WindowStart   time.Time
	WindowEnd     time.Time
	TracesFetched int
	TreesBuilt    int
}

// SaveTick records metadata for one analysis tick.
func (s *Store) SaveTick(ctx context.Context, m TickMeta) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ticks (tick_id, window_start, window_end, traces_fetched, trees_built, started_at)
		VALUES (?, ?, ?, ?, ?, NOW())`,
		m.TickID, m.WindowStart.UTC(), m.WindowEnd.UTC(),
		m.TracesFetched, m.TreesBuilt,
	)
	return err
}

// SaveSpans flattens all span trees and persists every span with its full
// attribute map as a JSON blob. No filtering — the caller decides what to
// analyse; the store keeps everything for ad-hoc querying.
func (s *Store) SaveSpans(ctx context.Context, tickID string, trees [][]*tempo.Span) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO spans (tick_id, trace_id, span_id, parent_span_id, service, name, attrs, is_root, ingested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	tempo.Walk(flattenTrees(trees), func(parent, span *tempo.Span) {
		if err != nil {
			return
		}
		attrsJSON, jerr := json.Marshal(span.Attrs)
		if jerr != nil {
			err = jerr
			return
		}
		_, err = stmt.ExecContext(ctx,
			tickID, span.TraceID, span.SpanID, span.ParentSpanID,
			span.Service, span.Name, string(attrsJSON), parent == nil,
		)
	})
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SaveFindings persists all three finding types for one tick.
func (s *Store) SaveFindings(ctx context.Context, tickID string,
	roots []analysis.RootAnomaly,
	drops []analysis.BaggageDrop,
	gaps []analysis.LabelGap,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings
			(tick_id, kind, service, caller, callee, attribute,
			 drop_rate, dropped, total, as_callee, as_root, in_trace, in_metric, window_ts)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range roots {
		if _, err = stmt.ExecContext(ctx,
			tickID, "root_anomaly", f.Service, nil, nil, nil,
			f.DropRate, nil, nil, f.AsCallee, f.AsRoot, nil, nil, f.Window.UTC(),
		); err != nil {
			return err
		}
	}
	for _, f := range drops {
		if _, err = stmt.ExecContext(ctx,
			tickID, "baggage_drop", nil, f.Caller, f.Callee, f.Attribute,
			f.DropRate, f.Dropped, f.Total, nil, nil, nil, nil, f.Window.UTC(),
		); err != nil {
			return err
		}
	}
	for _, f := range gaps {
		if _, err = stmt.ExecContext(ctx,
			tickID, "label_gap", nil, f.Caller, f.Callee, f.Attribute,
			nil, nil, nil, nil, nil, f.InTrace, f.InMetric, f.Window.UTC(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// OrphanCreator is a service detected as creating fresh traceparents for outgoing
// calls instead of propagating the existing trace context.
type OrphanCreator struct {
	Service              string
	TracesAsCallee       int
	TracesAsOrphanRoot   int // root spans that made downstream calls
	TracesAsLeafRoot     int // root spans with no children (receiving_drop pattern)
}

// QueryOrphanCreators finds services that appear as root spans WITH children
// in some traces while appearing as non-root callees in others.
//
// A service in this result is creating a new traceparent for its outgoing
// calls rather than propagating the existing one — the entire downstream
// subtree is lost from the original trace.
//
// This is distinct from a receiving_drop (where the service is a leaf orphan
// with no children): here the service IS making downstream calls, just under
// a freshly generated trace context.
func (s *Store) QueryOrphanCreators(ctx context.Context) ([]OrphanCreator, error) {
	q := `
		WITH
		-- Traces where a service is a root AND called at least one child.
		orphan_roots AS (
			SELECT DISTINCT p.service, p.trace_id, 'with_children' AS root_kind
			FROM spans p
			JOIN spans c ON c.trace_id = p.trace_id AND c.parent_span_id = p.span_id
			WHERE p.is_root = true
		),
		-- Traces where a service is a root with NO children.
		leaf_roots AS (
			SELECT p.service, COUNT(DISTINCT p.trace_id) AS leaf_count
			FROM spans p
			WHERE p.is_root = true
			  AND NOT EXISTS (
				SELECT 1 FROM spans c
				WHERE c.trace_id = p.trace_id AND c.parent_span_id = p.span_id
			  )
			GROUP BY 1
		),
		-- Traces where a service is a callee (not root).
		as_callee AS (
			SELECT service, COUNT(DISTINCT trace_id) AS callee_count
			FROM spans
			WHERE is_root = false
			GROUP BY 1
		)
		SELECT
			o.service,
			COALESCE(a.callee_count, 0)          AS traces_as_callee,
			COUNT(DISTINCT o.trace_id)            AS traces_as_orphan_root,
			COALESCE(l.leaf_count, 0)             AS traces_as_leaf_root
		FROM orphan_roots o
		LEFT JOIN as_callee   a ON a.service = o.service
		LEFT JOIN leaf_roots  l ON l.service = o.service
		WHERE COALESCE(a.callee_count, 0) > 0
		GROUP BY 1, 2, 4
		ORDER BY 3 DESC
	`

	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("QueryOrphanCreators: %w", err)
	}
	defer rows.Close()

	var out []OrphanCreator
	for rows.Next() {
		var o OrphanCreator
		if err := rows.Scan(&o.Service, &o.TracesAsCallee,
			&o.TracesAsOrphanRoot, &o.TracesAsLeafRoot); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// BaggageDrop is a baggage drop finding produced by querying stored span data.
type BaggageDrop struct {
	Caller      string
	Callee      string
	DroppedKey  string
	TimesDropped int
	TotalCalls  int
	DropPct     float64
}

// QueryBaggageDrops performs a schema-agnostic baggage drop analysis over all
// stored spans using a self-join on (trace_id, parent_span_id).
//
// For every parent-child span pair it finds attribute keys that are present on
// the parent but absent on the child, then aggregates by (caller, callee, key).
//
// This complements the in-memory DetectBaggageDrops: it works across all stored
// ticks (not just the current one) and requires no prior knowledge of attribute names.
//
// otelFilter controls whether OTel semantic-convention keys (http.*, db.*, …)
// are excluded from results.
func (s *Store) QueryBaggageDrops(ctx context.Context, otelFilter bool) ([]BaggageDrop, error) {
	otelClause := ""
	if otelFilter {
		// Exclude keys that belong to OTel semantic convention namespaces.
		// These differ between parent and child for legitimate reasons (e.g.
		// http.method on an HTTP span vs db.system on a downstream DB span).
		otelClause = `WHERE NOT regexp_matches(d.dropped_key, '^(http|db|rpc|net|messaging|faas|peer|exception|event|span|otel|process|telemetry|service|code|thread|aws|gcp|azure|k8s|container|host|enduser|url|server|client|network|system|disk|cpu|memory)\.')`
	}

	q := fmt.Sprintf(`
		WITH pairs AS (
			SELECT
				p.service  AS caller,
				c.service  AS callee,
				json_keys(p.attrs) AS pkeys,
				json_keys(c.attrs) AS ckeys
			FROM spans c
			JOIN spans p
			  ON c.trace_id      = p.trace_id
			 AND c.parent_span_id = p.span_id
		),
		dropped AS (
			SELECT
				caller,
				callee,
				unnest(list_filter(pkeys, k -> NOT list_contains(ckeys, k))) AS dropped_key
			FROM pairs
		),
		totals AS (
			SELECT caller, callee, COUNT(*) AS total
			FROM pairs
			GROUP BY 1, 2
		)
		SELECT
			d.caller,
			d.callee,
			d.dropped_key,
			COUNT(*)                                    AS times_dropped,
			t.total                                     AS total_calls,
			ROUND(COUNT(*) * 100.0 / t.total, 1)        AS drop_pct
		FROM dropped d
		JOIN totals t USING (caller, callee)
		%s
		GROUP BY 1, 2, 3, t.total
		ORDER BY 4 DESC
	`, otelClause)

	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("QueryBaggageDrops: %w", err)
	}
	defer rows.Close()

	var out []BaggageDrop
	for rows.Next() {
		var d BaggageDrop
		if err := rows.Scan(&d.Caller, &d.Callee, &d.DroppedKey,
			&d.TimesDropped, &d.TotalCalls, &d.DropPct); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ServiceCoverage summarises baggage key presence for one service across all
// stored spans.
type ServiceCoverage struct {
	Service      string
	TotalSpans   int
	WithBaggage  int     // spans carrying at least one non-OTel attribute
	Coverage     float64 // WithBaggage / TotalSpans
	IsMiddleware bool    // appears as both caller and callee
}

// QueryBaggageCoverage returns per-service baggage coverage across all stored spans.
// Services with low coverage are candidates for missing context propagation.
//
// The query discovers baggage keys dynamically (excluding OTel semantic namespaces)
// so it works without any prior configuration of baggage_keys.
func (s *Store) QueryBaggageCoverage(ctx context.Context) ([]ServiceCoverage, error) {
	q := `
		WITH
		-- Flatten every attr key with its owning span. Unnest in FROM (not WHERE)
		-- to avoid DuckDB's restriction on correlated unnest expressions.
		flat_attrs AS (
			SELECT service, span_id, unnest(json_keys(attrs)) AS key
			FROM spans
		),
		-- Non-OTel keys that appear anywhere in the dataset — these are the
		-- likely baggage keys we care about for coverage.
		baggage_keys AS (
			SELECT DISTINCT key FROM flat_attrs
			WHERE NOT regexp_matches(key,
				'^(http|db|rpc|net|messaging|faas|peer|exception|event|span|otel|'
				'process|telemetry|service|code|thread|aws|gcp|azure|k8s|'
				'container|host|enduser|url|server|client|network|system|disk|cpu|memory)\.')
		),
		-- Spans that carry at least one baggage key.
		spans_with_baggage AS (
			SELECT DISTINCT fa.span_id
			FROM flat_attrs fa
			JOIN baggage_keys bk ON bk.key = fa.key
		),
		-- Per-service counts.
		service_stats AS (
			SELECT
				s.service,
				COUNT(*)             AS total_spans,
				COUNT(swb.span_id)   AS with_baggage
			FROM spans s
			LEFT JOIN spans_with_baggage swb ON swb.span_id = s.span_id
			GROUP BY 1
		),
		-- Parent span IDs seen across all spans (used to determine caller role).
		parent_ids AS (
			SELECT DISTINCT parent_span_id AS span_id
			FROM spans
			WHERE parent_span_id IS NOT NULL AND parent_span_id != ''
		),
		-- Per-service role: does it ever appear as a callee? as a caller?
		service_role AS (
			SELECT
				s.service,
				BOOL_OR(s.parent_span_id IS NOT NULL
				        AND s.parent_span_id != '')              AS as_callee,
				BOOL_OR(s.span_id IN (SELECT span_id FROM parent_ids)) AS as_caller
			FROM spans s
			GROUP BY 1
		)
		SELECT
			ss.service,
			ss.total_spans,
			ss.with_baggage,
			ROUND(ss.with_baggage * 1.0 / ss.total_spans, 4) AS coverage,
			(sr.as_callee AND sr.as_caller)                   AS is_middleware
		FROM service_stats ss
		JOIN service_role sr ON sr.service = ss.service
		ORDER BY coverage ASC, total_spans DESC
	`

	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("QueryBaggageCoverage: %w", err)
	}
	defer rows.Close()

	var out []ServiceCoverage
	for rows.Next() {
		var c ServiceCoverage
		if err := rows.Scan(&c.Service, &c.TotalSpans, &c.WithBaggage,
			&c.Coverage, &c.IsMiddleware); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS ticks (
	tick_id        TEXT PRIMARY KEY,
	window_start   TIMESTAMPTZ NOT NULL,
	window_end     TIMESTAMPTZ NOT NULL,
	traces_fetched INTEGER,
	trees_built    INTEGER,
	started_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS spans (
	tick_id        TEXT    NOT NULL,
	trace_id       TEXT    NOT NULL,
	span_id        TEXT    NOT NULL,
	parent_span_id TEXT,
	service        TEXT,
	name           TEXT,
	attrs          JSON,
	is_root        BOOLEAN,
	ingested_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS findings (
	tick_id    TEXT    NOT NULL,
	kind       TEXT    NOT NULL,
	service    TEXT,
	caller     TEXT,
	callee     TEXT,
	attribute  TEXT,
	drop_rate  DOUBLE,
	dropped    INTEGER,
	total      INTEGER,
	as_callee  INTEGER,
	as_root    INTEGER,
	in_trace   BOOLEAN,
	in_metric  BOOLEAN,
	window_ts  TIMESTAMPTZ
);
`

// flattenTrees returns a single root list usable with tempo.Walk.
func flattenTrees(trees [][]*tempo.Span) []*tempo.Span {
	var all []*tempo.Span
	for _, t := range trees {
		all = append(all, t...)
	}
	return all
}
