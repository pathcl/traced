package tempo

// Span is a node in a reconstructed trace tree.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Service      string
	Name         string
	Attrs        map[string]string
	Children     []*Span
}

// BuildTree reconstructs a span tree from a flat list of RawSpans.
// Spans whose ParentSpanID is empty or not found in the set become roots.
func BuildTree(raw []RawSpan) []*Span {
	index := make(map[string]*Span, len(raw))
	for i := range raw {
		r := &raw[i]
		index[r.SpanID] = &Span{
			TraceID:      r.TraceID,
			SpanID:       r.SpanID,
			ParentSpanID: r.ParentSpanID,
			Service:      r.Service,
			Name:         r.Name,
			Attrs:        r.Attrs,
		}
	}

	var roots []*Span
	for _, s := range index {
		if s.ParentSpanID == "" {
			roots = append(roots, s)
			continue
		}
		if parent, ok := index[s.ParentSpanID]; ok {
			parent.Children = append(parent.Children, s)
		} else {
			// Parent not in this trace fetch — treat as root.
			roots = append(roots, s)
		}
	}
	return roots
}

// Walk visits every span in depth-first order, calling fn for each.
func Walk(roots []*Span, fn func(parent, span *Span)) {
	for _, r := range roots {
		walk(nil, r, fn)
	}
}

func walk(parent, s *Span, fn func(parent, span *Span)) {
	fn(parent, s)
	for _, c := range s.Children {
		walk(s, c, fn)
	}
}
