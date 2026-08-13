package analysis

import (
	"sort"
	"strings"

	"github.com/pathcl/traced/internal/tempo"
)

// otelPrefixes are OpenTelemetry semantic convention namespaces. Attributes
// under these prefixes are instrumentation metadata, not propagated baggage.
var otelPrefixes = []string{
	"http.", "db.", "rpc.", "net.", "messaging.", "faas.",
	"peer.", "exception.", "event.", "span.", "otel.",
	"process.", "telemetry.", "service.", "code.", "thread.",
	"aws.", "gcp.", "azure.", "k8s.", "container.", "host.",
	"enduser.", "url.", "server.", "client.", "network.",
	"system.", "disk.", "cpu.", "memory.",
}

// IsOTelSemantic reports whether key belongs to an OTel semantic convention
// namespace. Exported so callers can filter independently.
func IsOTelSemantic(key string) bool {
	for _, prefix := range otelPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// parseBaggageHeader parses a W3C baggage header value and returns the member
// names. Properties after semicolons are ignored per the spec.
// e.g. "tenant=acme,country=es;prop=v" → ["tenant", "country"]
func parseBaggageHeader(v string) []string {
	var keys []string
	for _, member := range strings.Split(v, ",") {
		member = strings.TrimSpace(member)
		// Strip optional properties: "key=value;prop=pval" → "key=value"
		if sc := strings.IndexByte(member, ';'); sc >= 0 {
			member = member[:sc]
		}
		if eq := strings.IndexByte(member, '='); eq > 0 {
			k := strings.TrimSpace(member[:eq])
			if k != "" {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// DiscoverFromBaggageAttr scans all spans (not just roots) for an attribute
// whose key contains the substring "baggage" (case-insensitive) and parses
// its value as a W3C baggage header to extract the member names.
//
// OTel HTTP instrumentation commonly captures the incoming baggage header as
// a span attribute — e.g. http.request.header.baggage = "tenant=acme,country=es".
// This is more precise than guessing from non-OTel-semantic keys.
func DiscoverFromBaggageAttr(trees [][]*tempo.Span) []string {
	seen := map[string]struct{}{}
	for _, roots := range trees {
		tempo.Walk(roots, func(_, span *tempo.Span) {
			for k, v := range span.Attrs {
				if strings.Contains(strings.ToLower(k), "baggage") {
					for _, member := range parseBaggageHeader(v) {
						seen[member] = struct{}{}
					}
				}
			}
		})
	}
	if len(seen) == 0 {
		return nil
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// DiscoverBaggageKeys returns the set of attribute keys that are likely
// propagated W3C baggage members, using two strategies in priority order:
//
//  1. Look for any attribute whose key contains "baggage" and parse its value
//     as a W3C baggage header — handles http.request.header.baggage and
//     similar captures by OTel HTTP instrumentation libraries.
//  2. Fall back to root-span keys that are not OTel semantic conventions —
//     useful when the baggage header is not captured as a raw attribute.
//
// Use this when baggage_keys is not explicitly configured. The returned slice
// is sorted for deterministic output.
func DiscoverBaggageKeys(trees [][]*tempo.Span) []string {
	// Prefer the baggage-header attribute strategy — it is unambiguous.
	if keys := DiscoverFromBaggageAttr(trees); len(keys) > 0 {
		return keys
	}

	// Fallback: non-OTel-semantic keys on root spans.
	seen := map[string]struct{}{}
	for _, roots := range trees {
		for _, root := range roots {
			for k := range root.Attrs {
				if !IsOTelSemantic(k) && k != "" {
					seen[k] = struct{}{}
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
