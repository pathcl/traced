package testutil

import (
	"encoding/json"
	"fmt"
)

// PrometheusQueryResponse matches the Prometheus HTTP API instant query envelope.
type PrometheusQueryResponse struct {
	Status string                  `json:"status"`
	Data   PrometheusQueryData     `json:"data"`
}

type PrometheusQueryData struct {
	ResultType string                   `json:"resultType"`
	Result     []PrometheusVectorResult `json:"result"`
}

type PrometheusVectorResult struct {
	Metric map[string]string    `json:"metric"`
	Value  [2]json.RawMessage   `json:"value"`
}

// MetricBuilder constructs a synthetic Prometheus instant query response.
type MetricBuilder struct {
	results []PrometheusVectorResult
}

func NewMetricResponse() *MetricBuilder { return &MetricBuilder{} }

// AddSample adds one vector result with the given label set and value.
func (b *MetricBuilder) AddSample(labels map[string]string, value float64) *MetricBuilder {
	ts, _ := json.Marshal(float64(1700000000))
	val, _ := json.Marshal(fmt.Sprintf("%g", value))
	b.results = append(b.results, PrometheusVectorResult{
		Metric: labels,
		Value:  [2]json.RawMessage{ts, val},
	})
	return b
}

func (b *MetricBuilder) Build() PrometheusQueryResponse {
	return PrometheusQueryResponse{
		Status: "success",
		Data: PrometheusQueryData{
			ResultType: "vector",
			Result:     b.results,
		},
	}
}

func (b *MetricBuilder) MustJSON() []byte {
	data, err := json.Marshal(b.Build())
	if err != nil {
		panic(fmt.Sprintf("testutil: MetricBuilder.MustJSON: %v", err))
	}
	return data
}

// LabelValuesResponse is the Prometheus /api/v1/label/{name}/values envelope.
type LabelValuesResponse struct {
	Status string   `json:"status"`
	Data   []string `json:"data"`
}

func NewLabelValuesResponse(values ...string) []byte {
	data, err := json.Marshal(LabelValuesResponse{Status: "success", Data: values})
	if err != nil {
		panic(fmt.Sprintf("testutil: NewLabelValuesResponse: %v", err))
	}
	return data
}
