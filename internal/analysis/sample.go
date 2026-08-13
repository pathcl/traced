package analysis

import (
	"sort"

	"github.com/pathcl/traced/internal/tempo"
)

// SampleAttributeValues collects up to maxPerKey distinct non-empty values
// for each key across all spans in trees. The result map omits keys for which
// no values were found. Values within each key are sorted.
//
// Use this to validate that the tool is actually seeing the attribute values
// you expect before relying on drop/coverage findings.
func SampleAttributeValues(trees [][]*tempo.Span, keys []string, maxPerKey int) map[string][]string {
	if len(keys) == 0 {
		return nil
	}

	seen := make(map[string]map[string]struct{}, len(keys))
	for _, k := range keys {
		seen[k] = make(map[string]struct{})
	}

	for _, roots := range trees {
		tempo.Walk(roots, func(_, span *tempo.Span) {
			for _, k := range keys {
				v := span.Attrs[k]
				if v == "" || len(seen[k]) >= maxPerKey {
					continue
				}
				seen[k][v] = struct{}{}
			}
		})
	}

	out := make(map[string][]string, len(keys))
	for k, vals := range seen {
		if len(vals) == 0 {
			continue
		}
		list := make([]string, 0, len(vals))
		for v := range vals {
			list = append(list, v)
		}
		sort.Strings(list)
		out[k] = list
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
