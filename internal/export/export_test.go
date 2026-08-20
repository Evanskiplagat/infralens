package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, map[string]string{"hello": "world"}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out["hello"] != "world" {
		t.Errorf("unexpected JSON output: %v", out)
	}
}

func TestWriteResourcesCSV(t *testing.T) {
	var buf bytes.Buffer
	resources := []resource.Resource{
		{ID: "vpc/1", Kind: resource.KindVPC, Name: "main"},
		{ID: "subnet/1", Kind: resource.KindSubnet, Name: "public-a"},
	}
	if err := WriteResourcesCSV(&buf, resources); err != nil {
		t.Fatalf("WriteResourcesCSV returned error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), buf.String())
	}
}

func TestWriteDOT(t *testing.T) {
	vpc := resource.Resource{ID: "vpc/1", Kind: resource.KindVPC, Name: "main"}
	subnet := resource.Resource{ID: "subnet/1", Kind: resource.KindSubnet, Name: "public-a"}
	edges := []resource.Edge{resource.NewEdge(vpc.ID, subnet.ID, resource.RelContains)}
	g := graph.Build([]resource.Resource{vpc, subnet}, edges)

	var buf bytes.Buffer
	if err := WriteDOT(&buf, g); err != nil {
		t.Fatalf("WriteDOT returned error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "digraph infralens {") {
		t.Errorf("expected DOT output to start with digraph header, got %q", out)
	}
	if !strings.Contains(out, `"vpc/1" -> "subnet/1"`) {
		t.Errorf("expected DOT output to contain the vpc->subnet edge, got %q", out)
	}
}
