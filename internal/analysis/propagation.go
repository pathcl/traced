package analysis

import (
	"strings"
	"time"

	"github.com/pathcl/traced/internal/tempo"
)

// BaggagePropagationDrop is a finding for a service edge where the W3C baggage
// header stops being forwarded. This is distinct from a span attribute drop:
// it specifically tracks whether the baggage HTTP header itself flows between
// services, not whether application code extracts values from it.
type BaggagePropagationDrop struct {
	Caller     string    `json:"caller"`
	Callee     string    `json:"callee"`
	HeaderAttr string    `json:"header_attr"` // e.g. "http.request.header.baggage"
	DropRate   float64   `json:"drop_rate"`
	Dropped    int       `json:"dropped"`
	Total      int       `json:"total"`
	Window     time.Time `json:"window"`
}

// isBaggageHeaderAttr returns true for span attributes that represent a
// captured W3C baggage HTTP header. OTel HTTP server instrumentation
// produces "http.request.header.baggage"; simpler setups may use "baggage".
func isBaggageHeaderAttr(key string) bool {
	return key == "baggage" || strings.HasSuffix(key, ".baggage")
}

// DetectBaggagePropagation detects service edges where the W3C baggage header
// is not being forwarded to the downstream service.
//
// The signal is a span attribute that captures the incoming HTTP baggage header
// — most commonly "http.request.header.baggage" set by OTel HTTP server
// instrumentation. If a parent span carries this attribute but the child's span
// does not, the parent service did not include the baggage header on its outgoing
// request to the child.
//
// Returns nil if no baggage header attribute is found in the data — this means
// the instrumentation is not configured to capture request headers, and
// propagation cannot be assessed from trace data alone.
func DetectBaggagePropagation(trees [][]*tempo.Span, window time.Time) []BaggagePropagationDrop {
	// First pass: find which baggage header attribute key is present in this dataset.
	headerAttr := ""
outer:
	for _, roots := range trees {
		tempo.Walk(roots, func(_, span *tempo.Span) {
			if headerAttr != "" {
				return
			}
			for k := range span.Attrs {
				if isBaggageHeaderAttr(k) {
					headerAttr = k
					return
				}
			}
		})
		if headerAttr != "" {
			break outer
		}
	}
	if headerAttr == "" {
		return nil
	}

	// Second pass: edge-based drop detection.
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
			if parent.Attrs[headerAttr] != "" && span.Attrs[headerAttr] == "" {
				e.AttrDrops[headerAttr]++
			}
		})
	}

	var findings []BaggagePropagationDrop
	for key, e := range edges {
		dropped := e.AttrDrops[headerAttr]
		if dropped == 0 {
			continue
		}
		findings = append(findings, BaggagePropagationDrop{
			Caller:     key.Caller,
			Callee:     key.Callee,
			HeaderAttr: headerAttr,
			DropRate:   float64(dropped) / float64(e.Total),
			Dropped:    dropped,
			Total:      e.Total,
			Window:     window,
		})
	}
	return findings
}
