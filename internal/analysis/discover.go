package analysis

import (
	"sort"
	"strings"

	"github.com/pathcl/traced/internal/tempo"
)

// otelPrefixes are OpenTelemetry semantic convention namespaces. Attributes
// under these prefixes are instrumentation metadata, not application-level
// span attributes set by the service itself.
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

// DiscoverSpanAttributes inspects root spans across all trees and returns the
// set of attribute keys that are likely application-level span attributes —
// i.e. present on root spans and not part of any OTel semantic convention
// namespace (http.*, db.*, rpc.*, etc.).
//
// Use this as a fallback when span_attributes is not explicitly configured.
// The returned slice is sorted for deterministic output.
func DiscoverSpanAttributes(trees [][]*tempo.Span) []string {
	seen := map[string]struct{}{}
	for _, roots := range trees {
		for _, root := range roots {
			for k := range root.Attrs {
				if !IsOTelSemantic(k) && k != "" && !isBaggageHeaderAttr(k) {
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
