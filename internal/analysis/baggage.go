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

// SpanAttributeDrop is a finding for one edge that drops a specific attribute.
type SpanAttributeDrop struct {
	Caller    string    `json:"caller"`
	Callee    string    `json:"callee"`
	Attribute string    `json:"attribute"`
	DropRate  float64   `json:"drop_rate"`
	Dropped   int       `json:"dropped"`
	Total     int       `json:"total"`
	Window    time.Time `json:"window"`
}

// DetectSpanAttributeDrops walks span trees and finds edges where a configured
// span attribute present on a parent span is absent on the child span.
//
// attrs is the user-configured list of span attribute keys to track
// (config: span_attributes). Only attributes present on the parent are checked —
// if the parent doesn't carry it, no drop is recorded for that edge.
func DetectSpanAttributeDrops(trees [][]*tempo.Span, attrs []string, window time.Time) []SpanAttributeDrop {
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

			for _, attr := range attrs {
				parentHas := parent.Attrs[attr] != ""
				childHas := span.Attrs[attr] != ""
				if parentHas && !childHas {
					e.AttrDrops[attr]++
				}
			}
		})
	}

	var findings []SpanAttributeDrop
	for key, e := range edges {
		for attr, dropped := range e.AttrDrops {
			if dropped == 0 {
				continue
			}
			findings = append(findings, SpanAttributeDrop{
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
