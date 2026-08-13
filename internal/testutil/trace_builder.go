// Package testutil provides builders for synthetic OTLP traces and Prometheus
// metric responses used in tests across the traced codebase.
package testutil

import (
	"encoding/json"
	"fmt"
)

// OTLPTrace is the JSON envelope Tempo returns from /api/traces/{id}.
type OTLPTrace struct {
	Batches []OTLPBatch `json:"batches"`
}

type OTLPBatch struct {
	Resource   OTLPResource   `json:"resource"`
	ScopeSpans []OTLPScopeSpan `json:"scopeSpans"`
}

type OTLPResource struct {
	Attributes []OTLPKeyValue `json:"attributes"`
}

type OTLPScopeSpan struct {
	Spans []OTLPSpan `json:"spans"`
}

type OTLPSpan struct {
	TraceID      string         `json:"traceId"`
	SpanID       string         `json:"spanId"`
	ParentSpanID string         `json:"parentSpanId,omitempty"`
	Name         string         `json:"name"`
	StartTime    string         `json:"startTimeUnixNano"`
	Attributes   []OTLPKeyValue `json:"attributes"`
}

type OTLPKeyValue struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

func otlpStringVal(s string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"stringValue": s})
	return b
}

// spanSpec is the internal representation of a span before it's serialised.
type spanSpec struct {
	spanID       string
	parentSpanID string
	service      string
	name         string
	attrs        map[string]string
}

// TraceBuilder constructs a synthetic OTLP trace JSON.
type TraceBuilder struct {
	traceID string
	spans   []spanSpec
}

// NewTrace starts a builder for a trace with the given ID.
func NewTrace(traceID string) *TraceBuilder {
	return &TraceBuilder{traceID: traceID}
}

// AddSpan adds a span to the trace.
//   - spanID, parentSpanID: use "" for parentSpanID to make this a root span.
//   - service: value for the resource-level service.name attribute.
//   - attrs: span-level attributes (baggage keys, http.method, etc.).
func (b *TraceBuilder) AddSpan(spanID, parentSpanID, service, name string, attrs map[string]string) *TraceBuilder {
	b.spans = append(b.spans, spanSpec{
		spanID:       spanID,
		parentSpanID: parentSpanID,
		service:      service,
		name:         name,
		attrs:        attrs,
	})
	return b
}

// Build serialises the trace to the OTLP JSON format Tempo returns.
// Each unique service becomes its own batch (resource spans group).
func (b *TraceBuilder) Build() OTLPTrace {
	// Group spans by service.
	byService := make(map[string][]spanSpec)
	order := []string{}
	seen := map[string]bool{}
	for _, s := range b.spans {
		if !seen[s.service] {
			order = append(order, s.service)
			seen[s.service] = true
		}
		byService[s.service] = append(byService[s.service], s)
	}

	var batches []OTLPBatch
	for _, svc := range order {
		batch := OTLPBatch{
			Resource: OTLPResource{
				Attributes: []OTLPKeyValue{
					{Key: "service.name", Value: otlpStringVal(svc)},
				},
			},
		}
		var spans []OTLPSpan
		for _, ss := range byService[svc] {
			span := OTLPSpan{
				TraceID:      b.traceID,
				SpanID:       ss.spanID,
				ParentSpanID: ss.parentSpanID,
				Name:         ss.name,
				StartTime:    "1700000000000000000",
			}
			for k, v := range ss.attrs {
				span.Attributes = append(span.Attributes, OTLPKeyValue{
					Key:   k,
					Value: otlpStringVal(v),
				})
			}
			spans = append(spans, span)
		}
		batch.ScopeSpans = []OTLPScopeSpan{{Spans: spans}}
		batches = append(batches, batch)
	}
	return OTLPTrace{Batches: batches}
}

// MustJSON serialises the trace to JSON, panicking on error (safe for tests).
func (b *TraceBuilder) MustJSON() []byte {
	data, err := json.Marshal(b.Build())
	if err != nil {
		panic(fmt.Sprintf("testutil: TraceBuilder.MustJSON: %v", err))
	}
	return data
}

// TempoSearchResponse is the JSON envelope for /api/search.
type TempoSearchResponse struct {
	Traces []TempoSearchTrace `json:"traces"`
}

type TempoSearchTrace struct {
	TraceID         string `json:"traceID"`
	RootServiceName string `json:"rootServiceName"`
	RootTraceName   string `json:"rootTraceName"`
	DurationMs      uint32 `json:"durationMs"`
}

// SearchResponseBuilder constructs a synthetic Tempo search response.
type SearchResponseBuilder struct {
	traces []TempoSearchTrace
}

func NewSearchResponse() *SearchResponseBuilder { return &SearchResponseBuilder{} }

func (b *SearchResponseBuilder) AddTrace(traceID, rootService, rootName string, durationMs uint32) *SearchResponseBuilder {
	b.traces = append(b.traces, TempoSearchTrace{
		TraceID:         traceID,
		RootServiceName: rootService,
		RootTraceName:   rootName,
		DurationMs:      durationMs,
	})
	return b
}

func (b *SearchResponseBuilder) MustJSON() []byte {
	data, err := json.Marshal(TempoSearchResponse{Traces: b.traces})
	if err != nil {
		panic(fmt.Sprintf("testutil: SearchResponseBuilder.MustJSON: %v", err))
	}
	return data
}
