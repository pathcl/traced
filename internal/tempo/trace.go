package tempo

import "encoding/json"

// TraceResponse is Tempo's JSON envelope for /api/traces/{id}.
// Tempo returns OTLP JSON: batches → resource spans → scope spans → spans.
type TraceResponse struct {
	Batches []Batch `json:"batches"`
}

type Batch struct {
	Resource   Resource    `json:"resource"`
	ScopeSpans []ScopeSpan `json:"scopeSpans"`
}

type Resource struct {
	Attributes []KV `json:"attributes"`
}

type ScopeSpan struct {
	Spans []OTLPSpan `json:"spans"`
}

type OTLPSpan struct {
	TraceID      string `json:"traceId"`
	SpanID       string `json:"spanId"`
	ParentSpanID string `json:"parentSpanId"`
	Name         string `json:"name"`
	StartTime    string `json:"startTimeUnixNano"`
	Attributes   []KV   `json:"attributes"`
}

// RawSpan is the flattened representation used by the tree builder.
type RawSpan struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Service      string
	Name         string
	StartTime    string
	Attrs        map[string]string
}

func (tr *TraceResponse) flatten() []RawSpan {
	var spans []RawSpan
	for _, batch := range tr.Batches {
		service := kvString(batch.Resource.Attributes, "service.name")
		for _, ss := range batch.ScopeSpans {
			for _, s := range ss.Spans {
				spans = append(spans, RawSpan{
					TraceID:      s.TraceID,
					SpanID:       s.SpanID,
					ParentSpanID: s.ParentSpanID,
					Service:      service,
					Name:         s.Name,
					StartTime:    s.StartTime,
					Attrs:        kvMap(s.Attributes),
				})
			}
		}
	}
	return spans
}

func kvString(kvs []KV, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			var s struct{ StringValue string `json:"stringValue"` }
			if err := json.Unmarshal(kv.Value, &s); err == nil && s.StringValue != "" {
				return s.StringValue
			}
		}
	}
	return ""
}

func kvMap(kvs []KV) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		var s struct{ StringValue string `json:"stringValue"` }
		if err := json.Unmarshal(kv.Value, &s); err == nil {
			m[kv.Key] = s.StringValue
		}
	}
	return m
}
