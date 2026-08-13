package analysis

import (
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

// ServiceStats tracks how often a service appears as a callee vs. a root,
// and how many times it was a root that itself made outgoing calls.
type ServiceStats struct {
	AsCallee        int
	AsRoot          int
	RootWithChildren int // root spans that called at least one downstream service
}

// RootAnomaly is a finding where a service unexpectedly starts traces.
//
// Kind distinguishes the two failure modes:
//   - "receiving_drop":  the service is a root with no children — traceparent
//     was not forwarded to this service by its caller.
//   - "orphan_creator":  the service is a root WITH children — the service
//     received a traceparent correctly in other traces but creates a fresh
//     one when making outgoing calls, losing the chain.
type RootAnomaly struct {
	Service          string    `json:"service"`
	AsCallee         int       `json:"as_callee"`
	AsRoot           int       `json:"as_root"`
	RootWithChildren int       `json:"root_with_children"`
	DropRate         float64   `json:"drop_rate"`
	Kind             string    `json:"kind"` // "receiving_drop" | "orphan_creator" | "mixed"
	Window           time.Time `json:"window"`
}

// DetectRootAnomalies finds services that appear frequently as callees but also
// show up as trace roots. The Kind field on each finding distinguishes whether
// the root spans are leaf orphans (traceparent was not received) or roots with
// children (the service is creating fresh traceparents for outgoing calls).
func DetectRootAnomalies(trees [][]*tempo.Span, minCallee int, threshold float64, window time.Time) []RootAnomaly {
	stats := make(map[string]*ServiceStats)

	for _, roots := range trees {
		tempo.Walk(roots, func(parent, span *tempo.Span) {
			if _, ok := stats[span.Service]; !ok {
				stats[span.Service] = &ServiceStats{}
			}
			if parent != nil {
				stats[span.Service].AsCallee++
			} else {
				stats[span.Service].AsRoot++
				if len(span.Children) > 0 {
					stats[span.Service].RootWithChildren++
				}
			}
		})
	}

	var findings []RootAnomaly
	for svc, s := range stats {
		if s.AsCallee < minCallee {
			continue
		}
		rate := float64(s.AsRoot) / float64(s.AsCallee)
		if rate <= threshold {
			continue
		}
		findings = append(findings, RootAnomaly{
			Service:          svc,
			AsCallee:         s.AsCallee,
			AsRoot:           s.AsRoot,
			RootWithChildren: s.RootWithChildren,
			DropRate:         rate,
			Kind:             rootKind(s),
			Window:           window,
		})
	}
	return findings
}

// rootKind classifies the anomaly based on whether the root spans have children.
func rootKind(s *ServiceStats) string {
	leafRoots := s.AsRoot - s.RootWithChildren
	switch {
	case s.RootWithChildren > 0 && leafRoots == 0:
		// Every root span made downstream calls — service is creating fresh contexts.
		return "orphan_creator"
	case s.RootWithChildren == 0:
		// No root span made downstream calls — caller is dropping traceparent.
		return "receiving_drop"
	default:
		// Both patterns observed — needs manual investigation.
		return "mixed"
	}
}
