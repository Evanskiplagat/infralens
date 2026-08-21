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
	failOn := fs.String("fail-on", "", "Exit non-zero if any finding at or above this severity exists: info, low, medium, high")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	threshold, err := parseSeverity(*minSeverity)
	if err != nil {
		return err
	}
	failThreshold := findings.Severity("")
	if *failOn != "" {
		failThreshold, err = parseSeverity(*failOn)
		if err != nil {
			return err
		}
	}

	cfg, logger, err := loadConfigWithLogger(config.Config{DBPath: *dbPath, LogLevel: *logLevel})
	if err != nil {
		return err
	}
	logger.Debugf("opening findings store at %s", cfg.DBPath)
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scan, err := resolveScan(ctx, store, *scanID)
	if err != nil {
		return fmt.Errorf("resolve scan: %w", err)
	}
	logger.Infof("loading findings for scan %s", scan.ID)

	found, err := store.LoadFindings(ctx, scan.ID)
	if err != nil {
		return err
	}
	found = filterBySeverity(found, threshold)

	switch *format {
	case "json":
		if err := export.WriteJSON(os.Stdout, found); err != nil {
			return err
		}
	case "table":
		printFindingsTable(scan.ID, found)
	default:
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}

	if shouldFailOnFindings(found, failThreshold) {
		return fmt.Errorf("findings at or above %s severity detected", failThreshold)
	}
	return nil
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
