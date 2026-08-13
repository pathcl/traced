package analysis

import (
	"time"

	"github.com/pathcl/traced/internal/mimir"
	"github.com/pathcl/traced/internal/tempo"
)

// LabelGap is a finding where a trace attribute is absent from the metric label set.
// InTrace=true, InMetric=false → connector dimensions config is missing this attribute.
// InTrace=false, InMetric=true → stale metric series or sampling gap in traces.
type LabelGap struct {
	Caller    string    `json:"caller"`
	Callee    string    `json:"callee"`
	Attribute string    `json:"attribute,omitempty"`
	InTrace   bool      `json:"in_trace"`
	InMetric  bool      `json:"in_metric"`
	Window    time.Time `json:"window"`
}

// ServiceGraphEdge is a (client, server) pair observed in either source.
type ServiceGraphEdge struct {
	Client string
	Server string
}

// DetectLabelGaps compares edges observed in Tempo span trees against
// the label sets on the corresponding Mimir servicegraph metric series.
//
// metricSamples should come from:
//
//	count by (client, server, <baggageKeys...>) (traces_service_graph_request_total)
func DetectLabelGaps(
	trees [][]*tempo.Span,
	metricSamples []mimir.Sample,
	baggageKeys []string,
	window time.Time,
) []LabelGap {
	// Build set of attrs seen on trace edges.
	type edgeAttrSet map[string]bool // attr → present
	traceEdges := make(map[ServiceGraphEdge]edgeAttrSet)

	for _, roots := range trees {
		tempo.Walk(roots, func(parent, span *tempo.Span) {
			if parent == nil {
				return
			}
			edge := ServiceGraphEdge{Client: parent.Service, Server: span.Service}
			if traceEdges[edge] == nil {
				traceEdges[edge] = make(edgeAttrSet)
			}
			for _, attr := range baggageKeys {
				if span.Attrs[attr] != "" {
					traceEdges[edge][attr] = true
				}
			}
		})
	}

	// Build set of attrs seen on metric series per edge.
	metricEdges := make(map[ServiceGraphEdge]edgeAttrSet)
	for _, s := range metricSamples {
		edge := ServiceGraphEdge{Client: s.Labels["client"], Server: s.Labels["server"]}
		if edge.Client == "" || edge.Server == "" {
			continue
		}
		if metricEdges[edge] == nil {
			metricEdges[edge] = make(edgeAttrSet)
		}
		for _, attr := range baggageKeys {
			if s.Labels[attr] != "" {
				metricEdges[edge][attr] = true
			}
		}
	}

	var findings []LabelGap

	// Attr in trace but absent from metric → connector dimensions config gap.
	for edge, traceAttrs := range traceEdges {
		metricAttrs := metricEdges[edge]
		for attr := range traceAttrs {
			if !metricAttrs[attr] {
				findings = append(findings, LabelGap{
					Caller:    edge.Client,
					Callee:    edge.Server,
					Attribute: attr,
					InTrace:   true,
					InMetric:  false,
					Window:    window,
				})
			}
		}
	}

	// Edge in metric but never seen in trace sample → stale series or sampling gap.
	for edge := range metricEdges {
		if _, ok := traceEdges[edge]; !ok {
			findings = append(findings, LabelGap{
				Caller:   edge.Client,
				Callee:   edge.Server,
				InTrace:  false,
				InMetric: true,
				Window:   window,
			})
		}
	}

	return findings
}
