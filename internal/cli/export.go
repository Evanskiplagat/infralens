package cli

import (
	"context"
	"flag"
	"fmt"

	"infralens/internal/config"
	"infralens/internal/export"
	"infralens/internal/findings"
	"infralens/internal/graph"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func runExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	scanID := fs.String("scan", "latest", `Scan ID to export, or "latest"`)
	format := fs.String("format", "json", "Export format: json, csv, or dot")
	out := fs.String("out", "", "Output file path (defaults to stdout)")
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
	found, err := store.LoadFindings(ctx, scan.ID)
	if err != nil {
		return err
	}

	w, closeFn, err := openOutput(*out)
	if err != nil {
		return err
	}
	defer closeFn()

	switch *format {
	case "json":
		return export.WriteJSON(w, struct {
			Scan      resource.Scan       `json:"scan"`
			Resources []resource.Resource `json:"resources"`
			Edges     []resource.Edge     `json:"edges"`
			Findings  []findings.Finding  `json:"findings"`
		}{scan, resources, edges, found})
	case "csv":
		return export.WriteResourcesCSV(w, resources)
	case "dot":
		return export.WriteDOT(w, graph.Build(resources, edges))
	default:
		return fmt.Errorf("unknown format %q (want json, csv, or dot)", *format)
	}
}
