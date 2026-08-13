package mimir

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

// Sample is one result row from an instant PromQL query.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Query runs an instant PromQL query against Mimir.
func (c *Client) Query(ctx context.Context, promql string, ts time.Time) ([]Sample, error) {
	params := url.Values{}
	params.Set("query", promql)
	params.Set("time", fmt.Sprintf("%d", ts.Unix()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/v1/query?"+params.Encode(), nil)
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
		return nil, fmt.Errorf("mimir query: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Status != "success" {
		return nil, fmt.Errorf("mimir query: status=%s", envelope.Status)
	}

	samples := make([]Sample, 0, len(envelope.Data.Result))
	for _, r := range envelope.Data.Result {
		var val float64
		_ = json.Unmarshal(r.Value[1], &val)
		samples = append(samples, Sample{Labels: r.Metric, Value: val})
	}
	return samples, nil
}

// LabelValues returns all values for a given label name matching the optional metric selector.
func (c *Client) LabelValues(ctx context.Context, label, match string, start, end time.Time) ([]string, error) {
	params := url.Values{}
	params.Set("start", fmt.Sprintf("%d", start.Unix()))
	params.Set("end", fmt.Sprintf("%d", end.Unix()))
	if match != "" {
		params.Set("match[]", match)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/v1/label/"+url.PathEscape(label)+"/values?"+params.Encode(), nil)
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
		return nil, fmt.Errorf("mimir label values: status %d", resp.StatusCode)
	}

	var out struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (c *Client) setHeaders(r *http.Request) {
	if c.tenantID != "" {
		r.Header.Set("X-Scope-OrgID", c.tenantID)
	}
}
