package analysis

import (
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

// EdgeKey identifies a directed service call.
type EdgeKey struct {
	Caller, Callee string
}

// EdgeStats counts total calls and per-attribute drops for one edge.
type EdgeStats struct {
	Total     int
	AttrDrops map[string]int // attr → number of times callee was missing it
}

// BaggageDrop is a finding for one edge that drops a specific attribute.
type BaggageDrop struct {
	Caller    string    `json:"caller"`
	Callee    string    `json:"callee"`
	Attribute string    `json:"attribute"`
	DropRate  float64   `json:"drop_rate"`
	Dropped   int       `json:"dropped"`
	Total     int       `json:"total"`
	Window    time.Time `json:"window"`
}

// DetectBaggageDrops walks span trees and finds edges where a baggage attribute
// present on an ancestor disappears on a descendant.
//
// The root span is the authority: any attribute it carries is expected to be
// present on every span in the trace. We flag the first edge where it vanishes.
func DetectBaggageDrops(trees [][]*tempo.Span, baggageKeys []string, window time.Time) []BaggageDrop {
	edges := make(map[EdgeKey]*EdgeStats)

	for _, roots := range trees {
		tempo.Walk(roots, func(parent, span *tempo.Span) {
			if parent == nil {
				return
			}
			key := EdgeKey{Caller: parent.Service, Callee: span.Service}
			if _, ok := edges[key]; !ok {
				edges[key] = &EdgeStats{AttrDrops: make(map[string]int)}
			}
			e := edges[key]
			e.Total++

			for _, attr := range baggageKeys {
				parentHas := parent.Attrs[attr] != ""
				childHas := span.Attrs[attr] != ""
				if parentHas && !childHas {
					e.AttrDrops[attr]++
				}
			}
		})
	}

	var findings []BaggageDrop
	for key, e := range edges {
		for attr, dropped := range e.AttrDrops {
			if dropped == 0 {
				continue
			}
			findings = append(findings, BaggageDrop{
				Caller:    key.Caller,
				Callee:    key.Callee,
				Attribute: attr,
				DropRate:  float64(dropped) / float64(e.Total),
				Dropped:   dropped,
				Total:     e.Total,
				Window:    window,
			})
		}
	}
	return findings
}
