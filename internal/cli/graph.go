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
	resourceID := fs.String("resource", "", "Focus on a normalized resource ID (for example ec2_instance/i-123)")
	depth := fs.Int("depth", 1, "Relationship hops to include around --resource (0 includes only that resource)")
	format := fs.String("format", "text", "Output format: text, json, or dot")
	out := fs.String("out", "", "Write output to a file instead of stdout")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" && *format != "dot" {
		return fmt.Errorf("unknown format %q (want text, json, or dot)", *format)
	}
	if *depth < 0 {
		return fmt.Errorf("--depth must be non-negative")
	}
	depthSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "depth" {
			depthSet = true
		}
	})
	if depthSet && *resourceID == "" {
		return fmt.Errorf("--depth requires --resource")
	}

	cfg, logger, err := loadConfigWithLogger(config.Config{DBPath: *dbPath, LogLevel: *logLevel})
	if err != nil {
		return err
	}
	logger.Debugf("opening graph store at %s", cfg.DBPath)
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scan, err := resolveScan(ctx, store, *scanID)
	if err != nil {
		return fmt.Errorf("resolve scan: %w", err)
	}
	logger.Infof("loading graph data for scan %s", scan.ID)
	resources, err := store.LoadResources(ctx, scan.ID)
	if err != nil {
		return err
	}
	edges, err := store.LoadEdges(ctx, scan.ID)
	if err != nil {
		return err
	}
	g := graph.Build(resources, edges)
	if *resourceID != "" {
		resources, edges, err = g.Neighborhood(*resourceID, *depth)
		if err != nil {
			return err
		}
		g = graph.Build(resources, edges)
	}

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
