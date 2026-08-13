package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pathcl/traced/internal/analysis"
)

// Report aggregates all findings from one analysis tick.
type Report struct {
	Window            time.Time                  `json:"window"`
	BaggageKeys       []string                   `json:"baggage_keys,omitempty"`
	TracesSampled     int                        `json:"traces_sampled,omitempty"`
	AllServices       []string                   `json:"all_services,omitempty"`
	RootAnomalies     []analysis.RootAnomaly     `json:"root_anomalies"`
	BaggageDrops      []analysis.BaggageDrop     `json:"baggage_drops"`
	LabelGaps         []analysis.LabelGap        `json:"label_gaps"`
	CoverageAnomalies []analysis.CoverageAnomaly `json:"coverage_anomalies,omitempty"`
}

// WriteJSON encodes the report as indented JSON to w.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable writes a human-readable table to w.
func (r *Report) WriteTable(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "=== Root Anomalies (traceparent loss candidates) — %s ===\n", r.Window.Format(time.RFC3339))
	if len(r.RootAnomalies) == 0 {
		fmt.Fprintln(tw, "  none")
	} else {
		sort.Slice(r.RootAnomalies, func(i, j int) bool {
			return r.RootAnomalies[i].DropRate > r.RootAnomalies[j].DropRate
		})
		fmt.Fprintln(tw, "SERVICE\tAS_CALLEE\tAS_ROOT\tDROP_RATE")
		for _, a := range r.RootAnomalies {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%.4f\n", a.Service, a.AsCallee, a.AsRoot, a.DropRate)
		}
	}

	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "=== Baggage Drops (attribute propagation failures) ===")
	if len(r.BaggageDrops) == 0 {
		fmt.Fprintln(tw, "  none")
	} else {
		sort.Slice(r.BaggageDrops, func(i, j int) bool {
			return r.BaggageDrops[i].DropRate > r.BaggageDrops[j].DropRate
		})
		fmt.Fprintln(tw, "CALLER\tCALLEE\tATTRIBUTE\tDROPPED\tTOTAL\tDROP_RATE")
		for _, d := range r.BaggageDrops {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%.4f\n",
				d.Caller, d.Callee, d.Attribute, d.Dropped, d.Total, d.DropRate)
		}
	}

	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "=== Label Gaps (trace attr vs metric label mismatches) ===")
	if len(r.LabelGaps) == 0 {
		fmt.Fprintln(tw, "  none")
	} else {
		fmt.Fprintln(tw, "CALLER\tCALLEE\tATTRIBUTE\tIN_TRACE\tIN_METRIC")
		for _, g := range r.LabelGaps {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%v\n",
				g.Caller, g.Callee, g.Attribute, g.InTrace, g.InMetric)
		}
	}

	tw.Flush()
}

// WriteSummary writes a prioritised, actionable human-readable summary to w.
//
// Findings are grouped by severity so an operator reading the output knows
// exactly what to fix and in what order:
//
//	[CRITICAL]  middleware services carrying zero baggage
//	[HIGH]      leaf services with zero baggage / edges dropping specific keys
//	[MEDIUM]    services with partial coverage / orphan traceparent creators
//	[INFO]      services receiving requests without traceparent
//	[OK]        services with no propagation issues
func (r *Report) WriteSummary(w io.Writer) {
	keys := strings.Join(r.BaggageKeys, ", ")
	if keys == "" {
		keys = "(none discovered — run with baggage_keys or capture http.request.header.baggage)"
	}

	fmt.Fprintf(w, "=== Propagation Health — %s ===\n", r.Window.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(w, "Baggage keys:   %s\n", keys)
	fmt.Fprintf(w, "Traces sampled: %d   Services: %d\n\n",
		r.TracesSampled, len(r.AllServices))

	// Partition coverage anomalies by severity.
	var criticalMiddleware []analysis.CoverageAnomaly // 0% coverage, is middleware
	var highLeaf []analysis.CoverageAnomaly           // 0% coverage, leaf
	var partial []analysis.CoverageAnomaly            // 0 < coverage < 100%
	for _, c := range r.CoverageAnomalies {
		switch {
		case c.Coverage == 0 && c.IsMiddleware:
			criticalMiddleware = append(criticalMiddleware, c)
		case c.Coverage == 0:
			highLeaf = append(highLeaf, c)
		default:
			partial = append(partial, c)
		}
	}

	// Partition root anomalies by kind.
	var orphanCreators []analysis.RootAnomaly
	var receivingDrops []analysis.RootAnomaly
	var mixedRoots []analysis.RootAnomaly
	for _, ra := range r.RootAnomalies {
		switch ra.Kind {
		case "orphan_creator":
			orphanCreators = append(orphanCreators, ra)
		case "receiving_drop":
			receivingDrops = append(receivingDrops, ra)
		default:
			mixedRoots = append(mixedRoots, ra)
		}
	}

	anythingFound := len(r.CoverageAnomalies) > 0 ||
		len(r.BaggageDrops) > 0 ||
		len(r.RootAnomalies) > 0

	// Track which services have at least one finding (for the OK section).
	affectedServices := map[string]bool{}

	// --- CRITICAL ---
	if len(criticalMiddleware) > 0 {
		fmt.Fprintln(w, "[CRITICAL] Middleware services stripping ALL baggage (0% coverage):")
		fmt.Fprintln(w, "  These services sit between callers and callees but carry zero baggage on")
		fmt.Fprintf(w, "  any span. Every service downstream of them also loses context.\n\n")
		for _, c := range criticalMiddleware {
			fmt.Fprintf(w, "  %-30s  0 / %d spans carry baggage\n", c.Service, c.TotalSpans)
			affectedServices[c.Service] = true
		}
		fmt.Fprintln(w, "\n  → Enable the W3C BaggagePropagator in these services' OTel SDK config.")
		fmt.Fprintf(w, "    https://opentelemetry.io/docs/concepts/propagation/\n\n")
	}

	// --- HIGH (zero-coverage leaves) ---
	if len(highLeaf) > 0 {
		fmt.Fprintln(w, "[HIGH] Leaf services carrying no baggage:")
		fmt.Fprintln(w, "  End-of-chain services with zero coverage. No downstream impact,")
		fmt.Fprintf(w, "  but routing/observability context is lost at this service.\n\n")
		for _, c := range highLeaf {
			fmt.Fprintf(w, "  %-30s  0 / %d spans\n", c.Service, c.TotalSpans)
			affectedServices[c.Service] = true
		}
		fmt.Fprintf(w, "\n  → Enable the W3C BaggagePropagator (same fix as CRITICAL above).\n\n")
	}

	// --- HIGH (edge drops) ---
	if len(r.BaggageDrops) > 0 {
		fmt.Fprintln(w, "[HIGH] Edges where specific baggage keys disappear mid-chain:")
		fmt.Fprintln(w)
		for _, d := range r.BaggageDrops {
			fmt.Fprintf(w, "  %-20s → %-20s  [%s]   %.1f%%  (%d / %d calls)\n",
				d.Caller, d.Callee, d.Attribute, d.DropRate*100, d.Dropped, d.Total)
			affectedServices[d.Caller] = true
		}
		fmt.Fprintln(w, "\n  → The caller is not forwarding this key on the listed calls.")
		fmt.Fprintf(w, "    Verify outgoing request headers and baggage propagation on that code path.\n\n")
	}

	// --- MEDIUM (partial coverage) ---
	if len(partial) > 0 {
		fmt.Fprintln(w, "[MEDIUM] Services with inconsistent baggage coverage (<100%):")
		fmt.Fprintln(w)
		for _, c := range partial {
			role := "leaf"
			if c.IsMiddleware {
				role = "middleware"
			}
			fmt.Fprintf(w, "  %-30s  [%s]  %.0f%%  (%d / %d spans)\n",
				c.Service, role, c.Coverage*100, c.WithBaggage, c.TotalSpans)
			affectedServices[c.Service] = true
		}
		fmt.Fprintln(w, "\n  → These services propagate baggage on some requests but not all.")
		fmt.Fprintf(w, "    Check for code paths that create new contexts or strip outgoing headers.\n\n")
	}

	// --- MEDIUM (orphan creators) ---
	if len(orphanCreators) > 0 {
		fmt.Fprintln(w, "[MEDIUM] Services generating fresh traceparents for outgoing calls:")
		fmt.Fprintln(w, "  These services are creating a new trace context instead of propagating")
		fmt.Fprintln(w, "  the existing one. The entire downstream subtree is invisible in the")
		fmt.Fprintf(w, "  original trace.\n\n")
		for _, ra := range orphanCreators {
			fmt.Fprintf(w, "  %-30s  %d orphan roots with children  (normal callee: %d traces)\n",
				ra.Service, ra.RootWithChildren, ra.AsCallee)
			affectedServices[ra.Service] = true
		}
		fmt.Fprintln(w, "\n  → Look for context.Background(), new Span creation, or stripped headers")
		fmt.Fprintf(w, "    in outbound handlers (async workers, middleware, HTTP clients).\n\n")
	}

	// --- INFO (receiving drops) ---
	if len(receivingDrops) > 0 || len(mixedRoots) > 0 {
		fmt.Fprintln(w, "[INFO] Services receiving requests without a traceparent header:")
		fmt.Fprintln(w, "  These services start orphan root spans because their upstream callers")
		fmt.Fprintf(w, "  are not forwarding the traceparent header.\n\n")
		for _, ra := range receivingDrops {
			fmt.Fprintf(w, "  %-30s  %d orphan root spans\n", ra.Service, ra.AsRoot)
			affectedServices[ra.Service] = true
		}
		for _, ra := range mixedRoots {
			fmt.Fprintf(w, "  %-30s  %d orphan root spans (mixed — some also have children)\n",
				ra.Service, ra.AsRoot)
			affectedServices[ra.Service] = true
		}
		fmt.Fprintln(w, "\n  → Find which service sends requests to the above and fix its")
		fmt.Fprintf(w, "    outgoing header propagation (traceparent must be forwarded).\n\n")
	}

	// --- Label gaps (informational) ---
	inTrace := filterLabelGaps(r.LabelGaps, true, false)
	inMetric := filterLabelGaps(r.LabelGaps, false, true)
	if len(inTrace) > 0 {
		fmt.Fprintln(w, "[INFO] Attributes present in traces but missing from Mimir metric labels:")
		fmt.Fprintln(w)
		for _, g := range inTrace {
			fmt.Fprintf(w, "  %s → %s   [%s]\n", g.Caller, g.Callee, g.Attribute)
		}
		fmt.Fprintf(w, "\n  → Add these attributes to the 'dimensions' list in your OTel connector config.\n\n")
	}
	if len(inMetric) > 0 {
		fmt.Fprintln(w, "[INFO] Metric label edges not seen in trace sample:")
		fmt.Fprintln(w)
		for _, g := range inMetric {
			fmt.Fprintf(w, "  %s → %s\n", g.Caller, g.Callee)
		}
		fmt.Fprintf(w, "\n  → Stale metric series (decommissioned service) or sample too small.\n\n")
	}

	// --- OK ---
	if !anythingFound {
		fmt.Fprintln(w, "[OK] No propagation issues detected across all sampled traces.")
		return
	}
	var healthy []string
	for _, svc := range r.AllServices {
		if !affectedServices[svc] {
			healthy = append(healthy, svc)
		}
	}
	if len(healthy) > 0 {
		fmt.Fprintf(w, "[OK] No issues detected for: %s\n", strings.Join(healthy, ", "))
	}
}

func filterLabelGaps(gaps []analysis.LabelGap, inTrace, inMetric bool) []analysis.LabelGap {
	var out []analysis.LabelGap
	for _, g := range gaps {
		if g.InTrace == inTrace && g.InMetric == inMetric {
			out = append(out, g)
		}
	}
	return out
}
