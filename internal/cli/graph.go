package cli

import (
	"context"
	"flag"
	"fmt"

	"infralens/internal/config"
	"infralens/internal/export"
	"infralens/internal/graph"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func runGraph(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	scanID := fs.String("scan", "latest", `Scan ID to load, or "latest"`)
	format := fs.String("format", "text", "Output format: text, json, or dot")
	out := fs.String("out", "", "Write output to a file instead of stdout")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(config.Config{DBPath: *dbPath})
	if err != nil {
		return err
	}
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scan, err := resolveScan(ctx, store, *scanID)
	if err != nil {
		return fmt.Errorf("resolve scan: %w", err)
	}
	resources, err := store.LoadResources(ctx, scan.ID)
	if err != nil {
		return err
	}
	edges, err := store.LoadEdges(ctx, scan.ID)
	if err != nil {
		return err
	}
	g := graph.Build(resources, edges)

	w, closeFn, err := openOutput(*out)
	if err != nil {
		return err
	}
	defer closeFn()

	switch *format {
	case "json":
		return export.WriteJSON(w, struct {
			Resources []resource.Resource `json:"resources"`
			Edges     []resource.Edge     `json:"edges"`
		}{resources, edges})
	case "dot":
		return export.WriteDOT(w, g)
	case "text":
		for _, r := range resources {
			fmt.Fprintf(w, "%s (%s)\n", r.Name, r.Kind)
		}
		for _, e := range edges {
			fmt.Fprintf(w, "  %s --%s--> %s\n", e.From, e.Type, e.To)
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want text, json, or dot)", *format)
	}
}
