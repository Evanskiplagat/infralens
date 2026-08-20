package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"infralens/internal/config"
	"infralens/internal/export"
	"infralens/internal/findings"
	"infralens/internal/storage/sqlite"
)

func runFindings(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	scanID := fs.String("scan", "latest", `Scan ID to load, or "latest"`)
	format := fs.String("format", "table", "Output format: table or json")
	minSeverity := fs.String("severity", "low", "Minimum severity to include: info, low, medium, high")
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

	found, err := store.LoadFindings(ctx, scan.ID)
	if err != nil {
		return err
	}
	found = filterBySeverity(found, findings.Severity(*minSeverity))

	switch *format {
	case "json":
		return export.WriteJSON(os.Stdout, found)
	case "table":
		printFindingsTable(scan.ID, found)
		return nil
	default:
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}
}

func printFindingsTable(scanID string, found []findings.Finding) {
	if len(found) == 0 {
		fmt.Printf("no findings for scan %s\n", scanID)
		return
	}
	fmt.Printf("%-10s %-30s %-40s\n", "SEVERITY", "RULE", "RESOURCE")
	for _, f := range found {
		fmt.Printf("%-10s %-30s %-40s\n", f.Severity, f.RuleID, f.ResourceID)
	}
}
