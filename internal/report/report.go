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
	Window            time.Time                         `json:"window"`
	SpanAttributes    []string                          `json:"span_attributes,omitempty"`
	BaggageHeaderAttr string                            `json:"baggage_header_attribute,omitempty"`
	AttributeSamples  map[string][]string               `json:"attribute_samples,omitempty"`
	TracesSampled     int                               `json:"traces_sampled,omitempty"`
	AllServices       []string                          `json:"all_services,omitempty"`
	RootAnomalies     []analysis.RootAnomaly            `json:"root_anomalies"`
	BaggageDrops      []analysis.BaggagePropagationDrop `json:"baggage_drops,omitempty"`
	AttributeDrops    []analysis.SpanAttributeDrop      `json:"attribute_drops"`
	LabelGaps         []analysis.LabelGap               `json:"label_gaps"`
	CoverageAnomalies []analysis.CoverageAnomaly        `json:"coverage_anomalies,omitempty"`
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
	fmt.Fprintln(tw, "=== Baggage Header Drops (W3C baggage not forwarded) ===")
	if len(r.BaggageDrops) == 0 {
		fmt.Fprintln(tw, "  none (or http.request.header.baggage not captured by instrumentation)")
	} else {
		fmt.Fprintln(tw, "CALLER\tCALLEE\tHEADER_ATTR\tDROPPED\tTOTAL\tDROP_RATE")
		for _, d := range r.BaggageDrops {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%.4f\n",
				d.Caller, d.Callee, d.HeaderAttr, d.Dropped, d.Total, d.DropRate)
		}
	}

	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "=== Span Attribute Drops (configured attributes missing mid-chain) ===")
	if len(r.AttributeDrops) == 0 {
		fmt.Fprintln(tw, "  none")
	} else {
		sort.Slice(r.AttributeDrops, func(i, j int) bool {
			return r.AttributeDrops[i].DropRate > r.AttributeDrops[j].DropRate
		})
		fmt.Fprintln(tw, "CALLER\tCALLEE\tATTRIBUTE\tDROPPED\tTOTAL\tDROP_RATE")
		for _, d := range r.AttributeDrops {
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
// Two distinct propagation problems are reported separately:
//   - Baggage header drops: the W3C baggage HTTP header is not being forwarded
//     between services (detected via http.request.header.baggage span attr).
//   - Span attribute drops: specific configured attributes (span_attributes)
//     are present on a parent span but absent on the child's span.
func (r *Report) WriteSummary(w io.Writer) {
	attrs := strings.Join(r.SpanAttributes, ", ")
	if attrs == "" {
		attrs = "(none configured — set span_attributes or run once to discover)"
	}

	baggageAttrLabel := r.BaggageHeaderAttr
	if baggageAttrLabel == "" {
		baggageAttrLabel = "(auto-detect)"
	}

	fmt.Fprintf(w, "=== Propagation Health — %s ===\n", r.Window.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(w, "Span attributes tracked: %s\n", attrs)
	fmt.Fprintf(w, "Baggage header attribute: %s\n", baggageAttrLabel)
	fmt.Fprintf(w, "Traces sampled: %d   Services: %d\n\n",
		r.TracesSampled, len(r.AllServices))

	// --- Attribute samples ---
	if len(r.AttributeSamples) > 0 {
		fmt.Fprintln(w, "[INFO] Sample values collected for tracked span attributes:")
		keys := make([]string, 0, len(r.AttributeSamples))
		for k := range r.AttributeSamples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %-30s  %s\n", k, strings.Join(r.AttributeSamples[k], ", "))
		}
		fmt.Fprintln(w)
	}

	affectedServices := map[string]bool{}

	// --- W3C baggage header propagation ---
	if len(r.BaggageDrops) > 0 {
		fmt.Fprintln(w, "[HIGH] W3C baggage header not forwarded at these edges:")
		fmt.Fprintln(w, "  The baggage HTTP header was received by the caller but not sent")
		fmt.Fprintf(w, "  to the callee. Baggage members are lost for the entire downstream subtree.\n\n")
		for _, d := range r.BaggageDrops {
			fmt.Fprintf(w, "  %-20s → %-20s  %.1f%%  (%d / %d calls)  [via %s]\n",
				d.Caller, d.Callee, d.DropRate*100, d.Dropped, d.Total, d.HeaderAttr)
			affectedServices[d.Caller] = true
		}
		fmt.Fprintln(w, "\n  → Check that the caller's OTel SDK injects baggage on outgoing requests.")
		fmt.Fprintf(w, "    The BaggagePropagator must be in the propagator chain for all HTTP clients.\n\n")
	} else if r.TracesSampled > 0 {
		fmt.Fprintln(w, "[INFO] Baggage header propagation: no data.")
		if r.BaggageHeaderAttr != "" {
			fmt.Fprintf(w, "  Attribute %q was not found in any sampled span.\n", r.BaggageHeaderAttr)
			fmt.Fprintf(w, "  Verify instrumentation captures the baggage request header.\n\n")
		} else {
			fmt.Fprintln(w, "  No baggage header attribute found. Set baggage_header_attribute in")
			fmt.Fprintf(w, "  config.yaml, or verify OTel HTTP instrumentation captures the baggage header.\n\n")
		}
	}

	// --- Span attribute coverage ---
	var criticalMiddleware []analysis.CoverageAnomaly
	var highLeaf []analysis.CoverageAnomaly
	var partial []analysis.CoverageAnomaly
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

	if len(criticalMiddleware) > 0 {
		fmt.Fprintln(w, "[CRITICAL] Middleware services with no configured span attributes (0% coverage):")
		fmt.Fprintln(w, "  These services sit between callers and callees but carry none of the")
		fmt.Fprintf(w, "  configured span_attributes on any span.\n\n")
		for _, c := range criticalMiddleware {
			fmt.Fprintf(w, "  %-30s  0 / %d spans\n", c.Service, c.TotalSpans)
			affectedServices[c.Service] = true
		}
		fmt.Fprintln(w)
	}

	if len(highLeaf) > 0 {
		fmt.Fprintln(w, "[HIGH] Leaf services with no configured span attributes:")
		fmt.Fprintln(w)
		for _, c := range highLeaf {
			fmt.Fprintf(w, "  %-30s  0 / %d spans\n", c.Service, c.TotalSpans)
			affectedServices[c.Service] = true
		}
		fmt.Fprintln(w)
	}

	if len(r.AttributeDrops) > 0 {
		fmt.Fprintln(w, "[HIGH] Span attributes disappearing mid-chain:")
		fmt.Fprintln(w)
		for _, d := range r.AttributeDrops {
			fmt.Fprintf(w, "  %-20s → %-20s  [%s]   %.1f%%  (%d / %d calls)\n",
				d.Caller, d.Callee, d.Attribute, d.DropRate*100, d.Dropped, d.Total)
			affectedServices[d.Caller] = true
		}
		fmt.Fprintln(w, "\n  → The caller has the attribute on its span but does not pass it to the callee.")
		fmt.Fprintf(w, "    Check whether the callee reads these values and sets them on its own spans.\n\n")
	}

	if len(partial) > 0 {
		fmt.Fprintln(w, "[MEDIUM] Services with inconsistent span attribute coverage (<100%):")
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
		fmt.Fprintln(w)
	}

	// --- Traceparent / root anomalies ---
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

	if len(orphanCreators) > 0 {
		fmt.Fprintln(w, "[MEDIUM] Services generating fresh traceparents for outgoing calls:")
		fmt.Fprintln(w)
		for _, ra := range orphanCreators {
			fmt.Fprintf(w, "  %-30s  %d orphan roots with children  (normal callee: %d traces)\n",
				ra.Service, ra.RootWithChildren, ra.AsCallee)
			affectedServices[ra.Service] = true
		}
		fmt.Fprintln(w, "\n  → Look for context.Background(), new Span creation, or stripped headers")
		fmt.Fprintf(w, "    in outbound handlers (async workers, middleware, HTTP clients).\n\n")
	}

	if len(receivingDrops) > 0 || len(mixedRoots) > 0 {
		fmt.Fprintln(w, "[INFO] Services receiving requests without a traceparent header:")
		fmt.Fprintln(w)
		for _, ra := range receivingDrops {
			fmt.Fprintf(w, "  %-30s  %d orphan root spans\n", ra.Service, ra.AsRoot)
			affectedServices[ra.Service] = true
		}
		for _, ra := range mixedRoots {
			fmt.Fprintf(w, "  %-30s  %d orphan root spans (mixed)\n", ra.Service, ra.AsRoot)
			affectedServices[ra.Service] = true
		}
		fmt.Fprintln(w, "\n  → Find which upstream service calls these and fix its outgoing")
		fmt.Fprintf(w, "    header propagation (traceparent must be forwarded).\n\n")
	}

	// --- Label gaps ---
	inTrace := filterLabelGaps(r.LabelGaps, true, false)
	inMetric := filterLabelGaps(r.LabelGaps, false, true)
	if len(inTrace) > 0 {
		fmt.Fprintln(w, "[INFO] Attributes in traces but missing from Mimir metric labels:")
		fmt.Fprintln(w)
		for _, g := range inTrace {
			fmt.Fprintf(w, "  %s → %s   [%s]\n", g.Caller, g.Callee, g.Attribute)
		}
		fmt.Fprintf(w, "\n  → Add to 'dimensions' in your OTel connector config.\n\n")
	}
	if len(inMetric) > 0 {
		fmt.Fprintln(w, "[INFO] Metric label edges not seen in trace sample:")
		fmt.Fprintln(w)
		for _, g := range inMetric {
			fmt.Fprintf(w, "  %s → %s\n", g.Caller, g.Callee)
		}
		fmt.Fprintf(w, "\n  → Stale series or sample too small.\n\n")
	}

	// --- OK ---
	anythingFound := len(r.CoverageAnomalies) > 0 || len(r.AttributeDrops) > 0 ||
		len(r.BaggageDrops) > 0 || len(r.RootAnomalies) > 0
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
