package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"infralens/internal/config"
	"infralens/internal/diff"
	"infralens/internal/export"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func runDiff(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	from := fs.String("from", "", "Baseline scan ID (required)")
	to := fs.String("to", "latest", `Comparison scan ID, or "latest"`)
	format := fs.String("format", "table", "Output format: table or json")
	includeEdges := fs.Bool("include-edges", false, "Also compare resource relationships")
	failOnChange := fs.Bool("fail-on-change", false, "Exit non-zero when the report contains changes")
	out := fs.String("out", "", "Write the report to a file instead of stdout")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return errors.New("--from is required")
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}

	cfg, logger, err := loadConfigWithLogger(config.Config{DBPath: *dbPath, LogLevel: *logLevel})
	if err != nil {
		return err
	}
	logger.Debugf("opening diff store at %s", cfg.DBPath)
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	fromScan, err := resolveScan(ctx, store, *from)
	if err != nil {
		return fmt.Errorf("resolve --from scan: %w", err)
	}
	toScan, err := resolveScan(ctx, store, *to)
	if err != nil {
		return fmt.Errorf("resolve --to scan: %w", err)
	}
	logger.Infof("diffing scans %s -> %s", fromScan.ID, toScan.ID)

	fromResources, err := store.LoadResources(ctx, fromScan.ID)
	if err != nil {
		return err
	}
	toResources, err := store.LoadResources(ctx, toScan.ID)
	if err != nil {
		return err
	}

	d := diff.CompareResources(fromResources, toResources)
	var edgeDiff *diff.EdgeDiff
	if *includeEdges {
		fromEdges, err := store.LoadEdges(ctx, fromScan.ID)
		if err != nil {
			return fmt.Errorf("load --from edges: %w", err)
		}
		toEdges, err := store.LoadEdges(ctx, toScan.ID)
		if err != nil {
			return fmt.Errorf("load --to edges: %w", err)
		}
		compared := diff.CompareEdges(fromEdges, toEdges)
		edgeDiff = &compared
	}

	w, closeOutput, err := openOutput(*out)
	if err != nil {
		return err
	}
	// Close explicitly before returning the CI gate result, including on errors.
	writeErr := writeDiffReport(w, *format, fromScan, toScan, d, edgeDiff)
	closeErr := closeOutput()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if *failOnChange && (len(d.Added)+len(d.Removed)+len(d.Changed) > 0 ||
		(edgeDiff != nil && len(edgeDiff.Added)+len(edgeDiff.Removed) > 0)) {
		return errors.New("infrastructure changes detected")
	}
	return nil
}

func writeDiffReport(w io.Writer, format string, from, to resource.Scan, d diff.ResourceDiff, edges *diff.EdgeDiff) error {
	switch format {
	case "json":
		return export.WriteJSON(w, struct {
			diff.ResourceDiff
			Edges *diff.EdgeDiff `json:"Edges,omitempty"`
		}{d, edges})
	case "table":
		return printResourceDiff(w, from, to, d, edges)
	default:
		return fmt.Errorf("unknown format %q (want table or json)", format)
	}
}

func printResourceDiff(w io.Writer, from, to resource.Scan, d diff.ResourceDiff, edges *diff.EdgeDiff) error {
	if _, err := fmt.Fprintf(w, "diff %s -> %s\n  %d added, %d removed, %d changed, %d unchanged\n\n", from.ID, to.ID, len(d.Added), len(d.Removed), len(d.Changed), d.Unchanged); err != nil {
		return err
	}

	for _, r := range d.Added {
		if _, err := fmt.Fprintf(w, "  + %s (%s)\n", r.Name, r.Kind); err != nil {
			return err
		}
	}
	for _, r := range d.Removed {
		if _, err := fmt.Fprintf(w, "  - %s (%s)\n", r.Name, r.Kind); err != nil {
			return err
		}
	}
	for _, c := range d.Changed {
		if _, err := fmt.Fprintf(w, "  ~ %s (%s)\n", c.After.Name, c.After.Kind); err != nil {
			return err
		}
	}
	if edges != nil {
		if _, err := fmt.Fprintf(w, "\n  relationships: %d added, %d removed\n", len(edges.Added), len(edges.Removed)); err != nil {
			return err
		}
		for _, group := range []struct {
			mark  string
			items []resource.Edge
		}{{"+", edges.Added}, {"-", edges.Removed}} {
			for _, e := range group.items {
				if _, err := fmt.Fprintf(w, "  %s %s --%s--> %s\n", group.mark, e.From, e.Type, e.To); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
