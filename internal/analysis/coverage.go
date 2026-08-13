package analysis

import (
	"sort"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

// CoverageAnomaly flags a service whose spans rarely or never carry any of
// the expected baggage keys — a signal that the service is not extracting or
// forwarding the W3C baggage header.
//
// Coverage is only meaningful for services that sit in the middle of a call
// graph (they receive calls AND make downstream calls). Pure entry points
// inject baggage rather than propagate it; pure leaves don't forward.
// The IsMiddleware field distinguishes these cases.
type CoverageAnomaly struct {
	Service     string    `json:"service"`
	TotalSpans  int       `json:"total_spans"`
	WithBaggage int       `json:"with_baggage"`
	Coverage    float64   `json:"coverage"` // fraction 0.0–1.0
	IsMiddleware bool     `json:"is_middleware"` // appears as both caller and callee
	Window      time.Time `json:"window"`
}

// DetectNoCoverage finds services whose spans carry baggage keys at or below
// maxCoverage (0.0 = none at all, 0.1 = fewer than 10%, etc.).
//
// Only services with at least minSpans observed are considered, to avoid
// flagging services seen only once or twice in the sample.
//
// spanAttrs should come from config or DiscoverBaggageKeys. A span is
// counted as "carrying baggage" if it has at least one key present and non-empty.
func DetectNoCoverage(trees [][]*tempo.Span, spanAttrs []string, minSpans int, maxCoverage float64, window time.Time) []CoverageAnomaly {
	if len(spanAttrs) == 0 {
		return nil
	}

	type stats struct {
		total       int
		withBaggage int
		asCallee    bool
		asCaller    bool
	}
	m := map[string]*stats{}

	for _, roots := range trees {
		tempo.Walk(roots, func(parent, span *tempo.Span) {
			if m[span.Service] == nil {
				m[span.Service] = &stats{}
			}
			s := m[span.Service]
			s.total++

			for _, k := range spanAttrs {
				if span.Attrs[k] != "" {
					s.withBaggage++
					break // count each span once regardless of how many keys it has
				}
			}

			if parent != nil {
				s.asCallee = true
			}
			if len(span.Children) > 0 {
				s.asCaller = true
			}
		})
	}

	var out []CoverageAnomaly
	for svc, s := range m {
		if s.total < minSpans {
			continue
		}
		cov := float64(s.withBaggage) / float64(s.total)
		if cov > maxCoverage {
			continue
		}
		out = append(out, CoverageAnomaly{
			Service:      svc,
			TotalSpans:   s.total,
			WithBaggage:  s.withBaggage,
			Coverage:     cov,
			IsMiddleware: s.asCallee && s.asCaller,
			Window:       window,
		})
	}

	// Sort by coverage ascending (worst first), then by total spans descending.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Coverage != out[j].Coverage {
			return out[i].Coverage < out[j].Coverage
		}
		return out[i].TotalSpans > out[j].TotalSpans
	})
	return out
}
