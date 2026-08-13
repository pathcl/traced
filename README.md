# traced

A Go daemon that inspects Tempo traces and Mimir metrics to find two classes of problems in an OpenTelemetry pipeline:

1. **Traceparent loss** — services that should always be callees (children in a trace) but are showing up as root spans, meaning the `traceparent` header was dropped before the request reached them.
2. **Baggage drop** — span attributes (`tenant`, `country`, etc.) that are present on a parent span but missing on a child, meaning the W3C baggage header stopped being propagated at a specific service edge.
3. **Coverage gaps** — services whose spans never (or rarely) carry any baggage key at all, signalling that the service is not extracting or forwarding the W3C baggage header.
4. **Label gaps** — trace attributes that appear on spans in Tempo but are absent from the corresponding `traces_service_graph_request_total` label set in Mimir, indicating a missing `dimensions` entry in the OTel connector config.

## How it works

On each tick the tool:

1. Queries Tempo (three parallel TraceQL searches): a broad sample, a root-span hunt, and per-attribute gap queries.
2. Fetches full OTLP traces for each trace ID and reconstructs the span tree.
3. Discovers which baggage keys to track (see [Attribute discovery](#attribute-discovery)).
4. Queries Mimir for `traces_service_graph_request_total` grouped by all configured dimensions.
5. Runs four independent analyzers across the combined data.
6. Emits a severity-ranked summary (or JSON/table) to stdout.

No prior knowledge of which services are "entry points" is needed — the topology is inferred from the trace data itself.

## Build

```bash
go build -o traced ./cmd/traced
```

## Configuration

```yaml
# config.yaml
tempo:
  url: http://tempo:3200
  poll_interval: 5m      # how often to run a tick
  lookback: 10m          # how far back each tick queries
  sample_limit: 200      # max traces fetched per TraceQL query
  tenant_id: ""          # set to send X-Scope-OrgID; omit for single-tenant

mimir:
  url: http://mimir:9009
  tenant_id: ""          # same pattern as tempo

analysis:
  # baggage_keys: [tenant, country]  # pin specific keys; omit to auto-discover (recommended)
  root_anomaly_threshold: 0.001     # flag a service if as_root/as_callee exceeds this
  min_callee_count: 50              # ignore services seen fewer times than this

output:
  format: summary        # summary (default) | json | table
```

## Running

**Daemon** (polls every `poll_interval`, runs one tick immediately on start):

```bash
./traced --config config.yaml
```

**Single tick and exit** (useful for debugging or cron):

```bash
./traced --config config.yaml --once
```

**With DuckDB persistence** (append `--db` to either mode):

```bash
./traced --config config.yaml --db ./traced.db
./traced --config config.yaml --once --db ./traced.db
```

Each tick writes to three tables: `ticks`, `spans` (full attrs as JSON), `findings`.

## Attribute discovery

`baggage_keys` in config is optional. When omitted (or empty list), the tool auto-discovers which attributes represent propagated W3C baggage using two strategies, tried in order:

### Strategy 1 — baggage header attribute (preferred)

OTel HTTP instrumentation libraries commonly capture the incoming `baggage` HTTP header as a span attribute. The tool scans all spans for any attribute whose key contains the substring `baggage` (case-insensitive) and parses its value as a W3C baggage string to extract the member names.

Common attribute names this matches:

| SDK / instrumentation | Attribute name | Example value |
|---|---|---|
| OTel Java / Python / JS (HTTP server) | `http.request.header.baggage` | `tenant=acme,country=es` |
| Custom capture | `baggage` | `tenant=acme,country=es` |

If your services capture the header in any of these ways, no `baggage_keys` config is needed.

### Strategy 2 — non-OTel-semantic root-span keys (fallback)

If no baggage-header attribute is found, the tool inspects root spans and returns any attribute key that does not belong to an OTel semantic convention namespace (`http.*`, `db.*`, `rpc.*`, `net.*`, etc.). This catches custom attributes that services set directly on spans.

### Logging

Discovered keys are logged at the start of each tick:

```
INFO discovered baggage keys keys=[tenant country region]
```

**Auto-discovery is the default.** `baggage_keys` is empty by default, so the tool discovers keys from live span data on every tick. Set it explicitly only when you want deterministic, stable behaviour and targeted Mimir queries — for example, once you have confirmed the key names from a discovery run.

## Querying the DuckDB store

```bash
duckdb traced.db
```

### Which services are dropping baggage headers?

This is the primary ad-hoc query. It joins every parent-child span pair and finds attribute keys present on the parent that are absent on the child — no prior knowledge of attribute names required.

```sql
WITH pairs AS (
    SELECT
        p.service          AS caller,
        c.service          AS callee,
        json_keys(p.attrs) AS pkeys,
        json_keys(c.attrs) AS ckeys
    FROM spans c
    JOIN spans p
      ON c.trace_id       = p.trace_id
     AND c.parent_span_id = p.span_id
),
dropped AS (
    SELECT caller, callee,
           unnest(list_filter(pkeys, k -> NOT list_contains(ckeys, k))) AS dropped_key
    FROM pairs
),
totals AS (
    SELECT caller, callee, COUNT(*) AS total FROM pairs GROUP BY 1, 2
)
SELECT
    d.caller,
    d.callee,
    d.dropped_key,
    COUNT(*)                              AS times_dropped,
    t.total                               AS total_calls,
    ROUND(COUNT(*) * 100.0 / t.total, 1) AS drop_pct
FROM dropped d
JOIN totals t USING (caller, callee)
-- Exclude OTel semantic convention attributes (http.*, db.*, rpc.*, etc.)
-- which legitimately differ between parent and child spans.
WHERE NOT regexp_matches(d.dropped_key,
    '^(http|db|rpc|net|messaging|faas|peer|exception|event|span|otel|'
    'process|telemetry|service|code|thread|aws|gcp|azure|k8s|'
    'container|host|enduser|url|server|client|network|system|disk|cpu|memory)\.')
GROUP BY 1, 2, 3, t.total
ORDER BY times_dropped DESC;
```

Example output for a `frontend → api-gateway → payment-svc → billing-svc` pipeline where `billing-svc` never propagates baggage and `api-gateway` intermittently drops `country`:

```
┌─────────────┬─────────────┬─────────────┬──────────────┬─────────────┬──────────┐
│   caller    │   callee    │ dropped_key │ times_dropped│ total_calls │ drop_pct │
├─────────────┼─────────────┼─────────────┼──────────────┼─────────────┼──────────┤
│ payment-svc │ billing-svc │ tenant      │ 10           │ 10          │ 100.0    │
│ payment-svc │ billing-svc │ country     │ 7            │ 10          │ 70.0     │
│ api-gateway │ payment-svc │ country     │ 3            │ 10          │ 30.0     │
└─────────────┴─────────────┴─────────────┴──────────────┴─────────────┴──────────┘
```

**Reading this output:**

- `payment-svc → billing-svc | tenant | 100%` — billing-svc never propagates baggage. Fix: enable the W3C baggage propagator in billing-svc's OTel SDK config.
- `payment-svc → billing-svc | country | 70%` — country drops here only when payment-svc received it. The 30% where it doesn't appear at this edge is because api-gateway already dropped it upstream (attributed to the correct edge below).
- `api-gateway → payment-svc | country | 30%` — intermittent: api-gateway is not always forwarding the `baggage` header. Fix: check whether api-gateway strips or rewrites outgoing headers on certain code paths.

> **Drops are attributed to the first edge where they occur.** If `api-gateway` drops `country`, `payment-svc` never has it to forward, so the `payment-svc → billing-svc` edge correctly does not count those cases as drops. This makes the query a reliable guide to where to fix the problem, not just where the symptom is visible.

### Which services are creating fresh traceparents for outgoing calls?

A service that appears as a root WITH children in some traces — while appearing as a callee in others — is generating a new trace context for its downstream calls instead of propagating the existing one. The entire downstream subtree is invisible in the original trace.

```sql
WITH
orphan_roots AS (
    SELECT DISTINCT p.service, p.trace_id
    FROM spans p
    JOIN spans c ON c.trace_id = p.trace_id AND c.parent_span_id = p.span_id
    WHERE p.is_root = true
),
leaf_roots AS (
    SELECT p.service, COUNT(DISTINCT p.trace_id) AS leaf_count
    FROM spans p
    WHERE p.is_root = true
      AND NOT EXISTS (
        SELECT 1 FROM spans c
        WHERE c.trace_id = p.trace_id AND c.parent_span_id = p.span_id
      )
    GROUP BY 1
),
as_callee AS (
    SELECT service, COUNT(DISTINCT trace_id) AS callee_count
    FROM spans WHERE is_root = false
    GROUP BY 1
)
SELECT
    o.service,
    a.callee_count                     AS traces_as_callee,
    COUNT(DISTINCT o.trace_id)         AS traces_as_orphan_root,
    COALESCE(l.leaf_count, 0)          AS traces_as_leaf_root
FROM orphan_roots o
JOIN as_callee  a ON a.service = o.service
LEFT JOIN leaf_roots l ON l.service = o.service
GROUP BY 1, 2, 4
ORDER BY 3 DESC;
```

Example output:

```
┌─────────────┬────────────────┬────────────────────┬──────────────────┐
│   service   │ traces_as_callee│ traces_as_orphan_root│ traces_as_leaf_root│
├─────────────┼────────────────┼────────────────────┼──────────────────┤
│ api-gateway │ 20              │ 6                  │ 0                │
└─────────────┴────────────────┴────────────────────┴──────────────────┘
```

`api-gateway` appears as a callee in 20 complete traces but started 6 separate root traces that each have downstream children. It is generating a new `traceparent` for its outgoing calls. `billing-svc` (which has 3 leaf orphan roots) does **not** appear here — its pattern is `receiving_drop`, not `orphan_creator`.

### Other useful queries

```sql
-- Discover all attribute keys across all stored spans
SELECT DISTINCT unnest(json_keys(attrs)) AS key
FROM spans ORDER BY key;

-- Trend: drop rate per edge per hour
WITH pairs AS (
    SELECT p.service AS caller, c.service AS callee,
           json_keys(p.attrs) AS pkeys, json_keys(c.attrs) AS ckeys,
           c.ingested_at
    FROM spans c JOIN spans p
      ON c.trace_id = p.trace_id AND c.parent_span_id = p.span_id
),
dropped AS (
    SELECT caller, callee, DATE_TRUNC('hour', ingested_at) AS hour,
           unnest(list_filter(pkeys, k -> NOT list_contains(ckeys, k))) AS key
    FROM pairs
    WHERE NOT regexp_matches(key, '^(http|db|rpc|net)\.')
)
SELECT hour, caller, callee, key, COUNT(*) AS drops
FROM dropped
GROUP BY 1, 2, 3, 4 ORDER BY 1, 5 DESC;

-- Which connector dimension gaps appear most often?
SELECT caller, callee, attribute, COUNT(*) AS ticks_seen
FROM findings
WHERE kind = 'label_gap' AND in_trace = true AND in_metric = false
GROUP BY 1, 2, 3 ORDER BY 4 DESC;

-- Traceparent drop rate trend for a specific service
SELECT DATE_TRUNC('hour', window_ts) AS hour, AVG(drop_rate)
FROM findings
WHERE kind = 'root_anomaly' AND service = 'billing-svc'
GROUP BY 1 ORDER BY 1;
```

> **Note on dotted attribute keys**: OTel semantic attributes like `http.method` contain dots.
> Use the arrow operator (`->>`) instead of `json_extract_string` with JSONPath for these,
> since `$.http.method` is parsed as nested objects (`http` → `method`), not as the literal key:
> ```sql
> SELECT attrs->>'http.method' FROM spans WHERE service = 'api-gateway';
> ```

## Expected output

Structured log lines go to **stderr**. The report goes to **stdout**, so you can pipe them independently.

### stderr (slog)

```
2026/08/13 14:03:00 INFO starting daemon interval=5m0s
2026/08/13 14:03:00 INFO running analysis tick start=2026-08-13T13:53:00Z end=2026-08-13T14:03:00Z
2026/08/13 14:03:01 INFO discovered baggage keys keys=[country tenant]
2026/08/13 14:03:01 INFO fetching full traces count=47
2026/08/13 14:03:02 INFO built span trees traces=47
```

### stdout — summary report (`format: summary`, default)

Findings are grouped by severity. Each section names the affected service, quantifies the problem, and tells you what to fix.

```
=== Propagation Health — 2026-08-13T14:18:02Z ===
Baggage keys:   country, tenant
Traces sampled: 247   Services: 4

[CRITICAL] Middleware services stripping ALL baggage (0% coverage):
  These services sit between callers and callees but carry zero baggage on
  any span. Every service downstream of them also loses context.

  billing-svc                     0 / 150 spans carry baggage

  → Enable the W3C BaggagePropagator in these services' OTel SDK config.
    https://opentelemetry.io/docs/concepts/propagation/

[HIGH] Leaf services carrying no baggage:
  End-of-chain services with zero coverage. No downstream impact,
  but routing/observability context is lost at this service.

  payment-svc                     0 / 80 spans

  → Enable the W3C BaggagePropagator (same fix as CRITICAL above).

[HIGH] Edges where specific baggage keys disappear mid-chain:

  api-gateway          → payment-svc           [country]   30.0%  (30 / 100 calls)

  → The caller is not forwarding this key on the listed calls.
    Verify outgoing request headers and baggage propagation on that code path.

[MEDIUM] Services generating fresh traceparents for outgoing calls:
  These services are creating a new trace context instead of propagating
  the existing one. The entire downstream subtree is invisible in the original trace.

  api-gateway                     6 orphan roots with children  (normal callee: 20 traces)

  → Look for context.Background(), new Span creation, or stripped headers
    in outbound handlers (async workers, middleware, HTTP clients).

[INFO] Services receiving requests without a traceparent header:
  These services start orphan root spans because their upstream callers
  are not forwarding the traceparent header.

  billing-svc                     12 orphan root spans

  → Find which service sends requests to the above and fix its
    outgoing header propagation (traceparent must be forwarded).

[OK] No issues detected for: frontend
```

### stdout — JSON report (`format: json`)

Machine-readable. Useful for piping into alerting or storage systems. Includes all four finding types.

```json
{
  "window": "2026-08-13T14:03:02Z",
  "baggage_keys": ["country", "tenant"],
  "traces_sampled": 247,
  "all_services": ["api-gateway", "billing-svc", "frontend", "payment-svc"],
  "root_anomalies": [
    {
      "service": "api-gateway",
      "as_callee": 20,
      "as_root": 6,
      "root_with_children": 6,
      "drop_rate": 0.23,
      "kind": "orphan_creator",
      "window": "2026-08-13T14:03:02Z"
    }
  ],
  "baggage_drops": [
    {
      "caller": "api-gateway",
      "callee": "payment-svc",
      "attribute": "country",
      "drop_rate": 0.30,
      "dropped": 30,
      "total": 100,
      "window": "2026-08-13T14:03:02Z"
    }
  ],
  "label_gaps": [],
  "coverage_anomalies": [
    {
      "service": "billing-svc",
      "total_spans": 150,
      "with_baggage": 0,
      "coverage": 0,
      "is_middleware": true,
      "window": "2026-08-13T14:03:02Z"
    }
  ]
}
```

### stdout — table report (`format: table`)

```
=== Root Anomalies (traceparent loss candidates) — 2026-08-13T14:03:02Z ===
SERVICE       AS_CALLEE  AS_ROOT  DROP_RATE
api-gateway   20         6        0.2300

=== Baggage Drops (attribute propagation failures) ===
CALLER        CALLEE       ATTRIBUTE  DROPPED  TOTAL  DROP_RATE
api-gateway   payment-svc  country    30       100    0.3000

=== Label Gaps (trace attr vs metric label mismatches) ===
  none
```

## Reading the findings

### `root_anomaly`

A service that appears frequently as a callee but also shows up as a trace root. The `kind` field tells you which of two distinct problems is happening:

| `kind` | `root_with_children` | What it means | What to fix |
|---|---|---|---|
| `receiving_drop` | `0` | The service started an orphan root with **no children**. Its caller did not forward `traceparent`, so the service never knew it was part of a trace. | Find the upstream caller and ensure it propagates the `traceparent` header on every outgoing request. |
| `orphan_creator` | `> 0` | The service started an orphan root **and called downstream services** under the new context. It received `traceparent` correctly in other traces but generates a fresh one for its outgoing calls — losing the entire downstream subtree from the original trace. | Check whether the service is creating a new `context.Context` (Go), `Span` (Java/JS), or similar for outgoing calls instead of propagating the incoming one. Common in async handlers, background jobs, and middleware that strips headers. |
| `mixed` | partial | Both patterns observed on this service. | Investigate individually — two separate code paths may be responsible. |

Example JSON:

```json
{
  "service": "api-gateway",
  "as_callee": 847,
  "as_root": 14,
  "root_with_children": 14,
  "drop_rate": 0.0165,
  "kind": "orphan_creator",
  "window": "2026-08-13T14:03:02Z"
}
```

### `coverage_anomaly`

A service where fewer than 100% of observed spans carry any baggage key. The `is_middleware` field is the critical signal:

| `is_middleware` | `coverage` | What it means | Priority |
|---|---|---|---|
| `true` | `0.0` | Service sits between callers and callees but strips all baggage. Every downstream service also loses context. | **CRITICAL** — fix first |
| `false` | `0.0` | Leaf service with no baggage. No downstream impact but context is lost here. | HIGH |
| `true` or `false` | `0–1` | Service propagates baggage on some requests but not all. Likely a code-path issue. | MEDIUM |

Fix: ensure the service's OTel SDK is configured with the W3C `BaggagePropagator` in its propagator chain.

### Other findings

| Finding | What it means | What to fix |
|---|---|---|
| `baggage_drop` | `api-gateway → payment-svc`: a baggage key is present on the `api-gateway` span but missing on the `payment-svc` span. Dropped at this edge. | Check that `api-gateway` copies incoming baggage into outgoing requests on all code paths. |
| `label_gap` `in_trace=true, in_metric=false` | An attribute shows up on spans in Tempo but is absent from the `traces_service_graph_request_total` series in Mimir. | Add it to the `dimensions` list in your OTel connector servicegraph config. |
| `label_gap` `in_trace=false, in_metric=true` | A metric series exists for an edge but no matching spans were seen in the trace sample. | Stale metric series (service decommissioned) or sample too small — increase `sample_limit` or widen `lookback`. |

## Architecture

```
cmd/traced/          entrypoint — daemon loop + --once flag
internal/
  tempo/             HTTP client (TraceQL search + full trace fetch) + span tree builder
  mimir/             Prometheus HTTP client (instant query + label values)
  analysis/
    roots.go         root-span anomaly detector (traceparent loss)
    baggage.go       per-edge attribute drop detector
    coverage.go      per-service baggage coverage detector
    labels.go        trace-attr vs metric-label comparator
    discover.go      baggage key auto-discovery (baggage header attr + OTel heuristic)
  report/            summary / JSON / table output
  testutil/          OTLP trace builder + Prometheus metric builder (for tests)
config/              YAML config loader
```

## Testing

```bash
go test ./...
```

Tests use `httptest.Server` — no running Tempo or Mimir required. The `testutil` package provides builders for synthetic OTLP traces and Prometheus metric responses that mirror the exact wire format both services use.
