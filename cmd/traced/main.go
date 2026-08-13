package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/pathcl/traced/config"
	"github.com/pathcl/traced/internal/analysis"
	"github.com/pathcl/traced/internal/mimir"
	"github.com/pathcl/traced/internal/report"
	"github.com/pathcl/traced/internal/store"
	"github.com/pathcl/traced/internal/tempo"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	once := flag.Bool("once", false, "run a single analysis tick and exit")
	dbPath := flag.String("db", "", "path to DuckDB database file (omit to skip persistence)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	var st *store.Store
	if *dbPath != "" {
		st, err = store.Open(*dbPath)
		if err != nil {
			slog.Error("failed to open store", "path", *dbPath, "err", err)
			os.Exit(1)
		}
		defer st.Close()
		slog.Info("persistence enabled", "db", *dbPath)
	}

	tempoClient := tempo.NewClient(cfg.Tempo.URL, cfg.Tempo.TenantID)
	mimirClient := mimir.NewClient(cfg.Mimir.URL, cfg.Mimir.TenantID)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tick := func() {
		if err := runTick(ctx, cfg, tempoClient, mimirClient, st); err != nil {
			slog.Error("tick failed", "err", err)
		}
	}

	if *once {
		tick()
		return
	}

	slog.Info("starting daemon", "interval", cfg.Tempo.PollInterval)
	ticker := time.NewTicker(cfg.Tempo.PollInterval)
	defer ticker.Stop()

	tick()
	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		case <-ticker.C:
			tick()
		}
	}
}

func runTick(ctx context.Context, cfg *config.Config, tempoClient *tempo.Client, mimirClient *mimir.Client, st *store.Store) error {
	now := time.Now().UTC()
	start := now.Add(-cfg.Tempo.Lookback)
	tickID := uuid.New().String()

	slog.Info("running analysis tick", "tick_id", tickID, "start", start, "end", now)

	// --- Tempo queries ---

	broadResults, err := tempoClient.Search(ctx, `{}`, start, now, cfg.Tempo.SampleLimit)
	if err != nil {
		return fmt.Errorf("tempo broad search: %w", err)
	}

	orphanResults, err := tempoClient.Search(ctx, `{rootSpans=true}`, start, now, cfg.Tempo.SampleLimit)
	if err != nil {
		slog.Warn("tempo orphan search failed, skipping", "err", err)
		orphanResults = nil
	}

	// Targeted gap queries only when span_attributes are explicitly configured.
	var gapResults []tempo.SearchResult
	for _, key := range cfg.Analysis.SpanAttributes {
		q := fmt.Sprintf(`{span.%s = ""}`, key)
		limit := cfg.Tempo.SampleLimit
		if n := len(cfg.Analysis.SpanAttributes); n > 1 {
			limit /= n
		}
		res, err := tempoClient.Search(ctx, q, start, now, limit)
		if err != nil {
			slog.Warn("tempo attribute gap search failed", "key", key, "err", err)
			continue
		}
		gapResults = append(gapResults, res...)
	}

	traceIDs := dedupeIDs(broadResults, orphanResults, gapResults)
	slog.Info("fetching full traces", "count", len(traceIDs))

	var trees [][]*tempo.Span
	for _, id := range traceIDs {
		raw, err := tempoClient.FetchTrace(ctx, id)
		if err != nil {
			slog.Warn("failed to fetch trace", "traceID", id, "err", err)
			continue
		}
		if roots := tempo.BuildTree(raw); len(roots) > 0 {
			trees = append(trees, roots)
		}
	}
	slog.Info("built span trees", "traces", len(trees))

	// --- Resolve span attributes to track ---
	// Use the configured list; fall back to discovery when not set.
	spanAttrs := cfg.Analysis.SpanAttributes
	if len(spanAttrs) == 0 {
		spanAttrs = analysis.DiscoverSpanAttributes(trees)
		if len(spanAttrs) > 0 {
			slog.Info("discovered span attributes", "attrs", spanAttrs)
		}
	}

	// --- Mimir: servicegraph label coverage ---
	dims := buildDimsByClause(spanAttrs)
	sgQuery := fmt.Sprintf(`count by (client, server%s) (traces_service_graph_request_total)`, dims)
	metricSamples, err := mimirClient.Query(ctx, sgQuery, now)
	if err != nil {
		slog.Warn("mimir servicegraph query failed, skipping label gap analysis", "err", err)
	}

	// --- Analysis ---
	rootAnomalies := analysis.DetectRootAnomalies(trees, cfg.Analysis.MinCalleeCount, cfg.Analysis.RootAnomalyThreshold, now)
	baggageDrops := analysis.DetectBaggagePropagation(trees, now)
	attributeDrops := analysis.DetectSpanAttributeDrops(trees, spanAttrs, now)
	labelGaps := analysis.DetectLabelGaps(trees, metricSamples, spanAttrs, now)
	coverageAnomalies := analysis.DetectNoCoverage(trees, spanAttrs, cfg.Analysis.MinCalleeCount, 0.99, now)

	allServices := collectServices(trees)

	rpt := &report.Report{
		Window:            now,
		SpanAttributes:    spanAttrs,
		TracesSampled:     len(traceIDs),
		AllServices:       allServices,
		RootAnomalies:     rootAnomalies,
		BaggageDrops:      baggageDrops,
		AttributeDrops:    attributeDrops,
		LabelGaps:         labelGaps,
		CoverageAnomalies: coverageAnomalies,
	}

	// --- Persist (optional) ---
	if st != nil {
		meta := store.TickMeta{
			TickID:        tickID,
			WindowStart:   start,
			WindowEnd:     now,
			TracesFetched: len(traceIDs),
			TreesBuilt:    len(trees),
		}
		if err := st.SaveTick(ctx, meta); err != nil {
			slog.Warn("failed to save tick metadata", "err", err)
		}
		if err := st.SaveSpans(ctx, tickID, trees); err != nil {
			slog.Warn("failed to save spans", "err", err)
		}
		if err := st.SaveFindings(ctx, tickID, rootAnomalies, attributeDrops, labelGaps); err != nil {
			slog.Warn("failed to save findings", "err", err)
		}
	}

	// --- Output ---
	switch cfg.Output.Format {
	case "table":
		rpt.WriteTable(os.Stdout)
	case "summary":
		rpt.WriteSummary(os.Stdout)
	default: // json
		if err := rpt.WriteJSON(os.Stdout); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	return nil
}

func collectServices(trees [][]*tempo.Span) []string {
	seen := map[string]struct{}{}
	for _, roots := range trees {
		tempo.Walk(roots, func(_, span *tempo.Span) {
			if span.Service != "" {
				seen[span.Service] = struct{}{}
			}
		})
	}
	svcs := make([]string, 0, len(seen))
	for s := range seen {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	return svcs
}

func dedupeIDs(sets ...[]tempo.SearchResult) []string {
	seen := make(map[string]struct{})
	var ids []string
	for _, set := range sets {
		for _, r := range set {
			if _, ok := seen[r.TraceID]; !ok {
				seen[r.TraceID] = struct{}{}
				ids = append(ids, r.TraceID)
			}
		}
	}
	return ids
}

func buildDimsByClause(keys []string) string {
	s := ""
	for _, k := range keys {
		s += ", " + k
	}
	return s
}
