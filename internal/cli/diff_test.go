package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infralens/internal/diff"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func TestDiffReportCompatibility(t *testing.T) {
	d := diff.CompareResources(nil, []resource.Resource{{ID: "a"}})
	var report bytes.Buffer
	if err := writeDiffReport(&report, "json", resource.Scan{}, resource.Scan{}, d, nil); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, report.Bytes()); err != nil {
		t.Fatal(err)
	}
	if compact.String() != string(want) {
		t.Fatalf("default JSON contract changed: %s", report.String())
	}
}

type failingDiffWriter struct{ err error }

func (w failingDiffWriter) Write(p []byte) (int, error) { return 0, w.err }

func TestDiffReportWriteErrors(t *testing.T) {
	want := errors.New("disk full")
	for _, format := range []string{"table", "json"} {
		if err := writeDiffReport(failingDiffWriter{want}, format, resource.Scan{}, resource.Scan{}, diff.ResourceDiff{}, nil); !errors.Is(err, want) {
			t.Fatalf("%s: expected write error, got %v", format, err)
		}
	}
}

func TestRunDiffChangeGate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "scans.db")
	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{"before", "after", "added", "changed"} {
		if err := store.CreateScan(ctx, resource.Scan{ID: id, Status: resource.ScanStatusComplete, StartedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		rs := []resource.Resource{{ID: "a"}, {ID: "b"}}
		if id == "added" {
			rs = append(rs, resource.Resource{ID: "c"})
		}
		if id == "changed" {
			rs[0].Name = "renamed"
		}
		if err := store.SaveResources(ctx, id, rs); err != nil {
			t.Fatal(err)
		}
	}
	edge := resource.NewEdge("a", "b", resource.RelContains)
	if err := store.SaveEdges(ctx, "after", []resource.Edge{edge}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		from  string
		to    string
		edges bool
		gate  bool
		fail  bool
	}{
		{"unchanged", "before", "before", true, true, false},
		{"resource addition", "before", "added", false, true, true},
		{"resource removal", "added", "before", false, true, true},
		{"resource update", "before", "changed", false, true, true},
		{"edges omitted", "before", "after", false, true, false},
		{"edge addition", "before", "after", true, true, true},
		{"edge removal", "after", "before", true, true, true},
		{"gate disabled", "before", "after", true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.json")
			args := []string{"--db", dbPath, "--from", tt.from, "--to", tt.to, "--format", "json", "--out", out, "--log-level", "error"}
			if tt.edges {
				args = append(args, "--include-edges")
			}
			if tt.gate {
				args = append(args, "--fail-on-change")
			}
			err := runDiff(ctx, args)
			if tt.fail {
				if err == nil || !strings.Contains(err.Error(), "infrastructure changes detected") {
					t.Fatalf("expected gate failure, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(out)
			if err != nil || !json.Valid(data) {
				t.Fatalf("expected complete report even on gate failure: %s, %v", data, err)
			}
			var result map[string]json.RawMessage
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if _, exists := result["Edges"]; exists != tt.edges {
				t.Fatalf("unexpected Edges field: %s", data)
			}
			if tt.name == "edge addition" {
				var changes diff.EdgeDiff
				if err := json.Unmarshal(result["Edges"], &changes); err != nil {
					t.Fatal(err)
				}
				if len(changes.Added) != 1 || changes.Added[0] != edge || changes.Removed == nil || len(changes.Removed) != 0 {
					t.Fatalf("unexpected relationship report: %+v", changes)
				}
			}
		})
	}
}

func TestDiffTableRelationships(t *testing.T) {
	edge := resource.NewEdge("a", "b", resource.RelContains)
	edges := diff.CompareEdges(nil, []resource.Edge{edge})
	var out bytes.Buffer
	if err := writeDiffReport(&out, "table", resource.Scan{ID: "before"}, resource.Scan{ID: "after"}, diff.ResourceDiff{}, &edges); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "relationships: 1 added, 0 removed") || !strings.Contains(out.String(), "+ a --contains--> b") {
		t.Fatalf("missing relationship details: %s", out.String())
	}
}
