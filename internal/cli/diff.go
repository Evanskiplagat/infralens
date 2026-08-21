package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

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
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return errors.New("--from is required")
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

	switch *format {
	case "json":
		return export.WriteJSON(os.Stdout, d)
	case "table":
		printResourceDiff(fromScan, toScan, d)
		return nil
	default:
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}
}

func printResourceDiff(from, to resource.Scan, d diff.ResourceDiff) {
	fmt.Printf("diff %s -> %s\n", from.ID, to.ID)
	fmt.Printf("  %d added, %d removed, %d changed, %d unchanged\n\n", len(d.Added), len(d.Removed), len(d.Changed), d.Unchanged)

	for _, r := range d.Added {
		fmt.Printf("  + %s (%s)\n", r.Name, r.Kind)
	}
	for _, r := range d.Removed {
		fmt.Printf("  - %s (%s)\n", r.Name, r.Kind)
	}
	for _, c := range d.Changed {
		fmt.Printf("  ~ %s (%s)\n", c.After.Name, c.After.Kind)
	}
}
