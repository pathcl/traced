package tempo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	base     string
	tenantID string
	http     *http.Client
}

func NewClient(baseURL, tenantID string) *Client {
	return &Client{
		base:     baseURL,
		tenantID: tenantID,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// SearchResult is a single entry from Tempo's search response.
type SearchResult struct {
	TraceID         string            `json:"traceID"`
	RootServiceName string            `json:"rootServiceName"`
	RootTraceName   string            `json:"rootTraceName"`
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	DurationMs      uint32            `json:"durationMs"`
	SpanSet         *SpanSet          `json:"spanSet"`
}

type SpanSet struct {
	Spans  []SearchSpan `json:"spans"`
	Matched int         `json:"matched"`
}

type SearchSpan struct {
	SpanID    string            `json:"spanID"`
	StartTime string            `json:"startTimeUnixNano"`
	Attrs     []KV              `json:"attributes"`
}

type KV struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// Search runs a TraceQL query and returns matching trace metadata.
func (c *Client) Search(ctx context.Context, query string, start, end time.Time, limit int) ([]SearchResult, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("start", fmt.Sprintf("%d", start.Unix()))
	params.Set("end", fmt.Sprintf("%d", end.Unix()))
	params.Set("limit", fmt.Sprintf("%d", limit))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/search?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tempo search: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Traces []SearchResult `json:"traces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Traces, nil
}

// FetchTrace retrieves the full span list for a single trace ID.
func (c *Client) FetchTrace(ctx context.Context, traceID string) ([]RawSpan, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/traces/"+traceID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tempo fetch trace %s: status %d", traceID, resp.StatusCode)
	}

	var out TraceResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.flatten(), nil
}

func (c *Client) setHeaders(r *http.Request) {
	if c.tenantID != "" {
		r.Header.Set("X-Scope-OrgID", c.tenantID)
	}
}
