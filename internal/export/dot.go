package export

import (
	"fmt"
	"io"

	"infralens/internal/graph"
)

// WriteDOT writes g as a Graphviz DOT digraph, e.g. for rendering with
// `dot -Tpng` or importing into other graph tooling.
func WriteDOT(w io.Writer, g *graph.Graph) error {
	if _, err := fmt.Fprintln(w, "digraph infralens {"); err != nil {
		return err
	}
	for _, r := range g.Resources {
		label := fmt.Sprintf("%s\\n%s", r.Kind, r.Name)
		if _, err := fmt.Fprintf(w, "  %q [label=%q];\n", r.ID, label); err != nil {
			return err
		}
	}
	for _, e := range g.Edges {
		if _, err := fmt.Fprintf(w, "  %q -> %q [label=%q];\n", e.From, e.To, e.Type); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "}")
	return err
}
