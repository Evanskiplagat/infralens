// Package export serializes scan data to InfraLens's automation-friendly
// output formats: JSON, CSV, and Graphviz/DOT.
package export

import (
	"encoding/json"
	"io"
)

// WriteJSON writes v to w as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
