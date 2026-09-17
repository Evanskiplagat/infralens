package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func TestRunGraphResourceSelection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "scan.db")
	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateScan(ctx, resource.Scan{ID: "scan", StartedAt: time.Now().UTC(), Status: resource.ScanStatusComplete}); err != nil {
		t.Fatal(err)
	}
	resources := []resource.Resource{
		{ID: "vpc/v-1", Name: "network", Kind: resource.KindVPC},
		{ID: "subnet/s-1", Name: "subnet", Kind: resource.KindSubnet},
		{ID: "ec2_instance/i-1", Name: "server", Kind: resource.KindEC2Instance},
	}
	edges := []resource.Edge{
		resource.NewEdge(resources[0].ID, resources[1].ID, resource.RelContains),
		resource.NewEdge(resources[1].ID, resources[2].ID, resource.RelContains),
	}
	if err := store.SaveResources(ctx, "scan", resources); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEdges(ctx, "scan", edges); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "text", "dot"} {
		t.Run(format, func(t *testing.T) {
			out := filepath.Join(dir, "graph."+format)
			args := []string{"--db", dbPath, "--scan", "scan", "--resource", resources[2].ID, "--format", format, "--out", out, "--log-level", "error"}
			if err := runGraph(ctx, args); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), resources[0].ID) || !strings.Contains(string(data), resources[1].ID) || !strings.Contains(string(data), resources[2].ID) {
				t.Fatalf("expected only instance and incoming subnet: %s", data)
			}
			if format == "json" {
				var result struct {
					Resources []resource.Resource `json:"resources"`
					Edges     []resource.Edge     `json:"edges"`
				}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Resources) != 2 || len(result.Edges) != 1 || result.Edges[0] != edges[1] {
					t.Fatalf("unexpected selection: %+v", result)
				}
			}
		})
	}

	out := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(out, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runGraph(ctx, []string{"--db", dbPath, "--scan", "scan", "--resource", "missing", "--out", out}); err == nil {
		t.Fatal("unknown resource should fail")
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "keep" {
		t.Fatal("failed selection must not overwrite existing output")
	}
}

func TestRunGraphRejectsInvalidSelectionFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--depth", "1"},
		{"--resource", "a", "--depth", "-1"},
		{"--resource", "a", "--format", "unknown"},
	} {
		dbPath := filepath.Join(t.TempDir(), "unused.db")
		if err := runGraph(context.Background(), append(args, "--db", dbPath)); err == nil {
			t.Fatalf("expected error for %v", args)
		}
		if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
			t.Fatal("invalid flags must be rejected before opening the database")
		}
	}
}
