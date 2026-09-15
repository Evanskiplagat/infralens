package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"

	"infralens/internal/config"
	"infralens/internal/export"
	"infralens/internal/findings"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func runFindings(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	scanID := fs.String("scan", "latest", `Scan ID to load, or "latest"`)
	baselineID := fs.String("baseline", "", "Completed scan ID to compare against; include only new or worsened findings")
	format := fs.String("format", "table", "Output format: table or json")
	minSeverity := fs.String("severity", "low", "Minimum severity to include: info, low, medium, high")
	failOn := fs.String("fail-on", "", "Exit non-zero if any finding at or above this severity exists: info, low, medium, high")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}
	if *baselineID == "latest" {
		return fmt.Errorf("--baseline requires an explicit scan ID")
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
	if *baselineID != "" {
		baseline, err := store.GetScan(ctx, *baselineID)
		if err != nil {
			return fmt.Errorf("resolve baseline scan: %w", err)
		}
		if err := validateBaseline(scan, baseline); err != nil {
			return err
		}
		previous, err := store.LoadFindings(ctx, baseline.ID)
		if err != nil {
			return fmt.Errorf("load baseline findings: %w", err)
		}
		found = newOrWorsenedFindings(found, previous)
	}
	fail := shouldFailOnFindings(found, failThreshold)
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

	if fail {
		return fmt.Errorf("findings at or above %s severity detected", failThreshold)
	}
	return nil
}

func validateBaseline(scan, baseline resource.Scan) error {
	if scan.ID == baseline.ID {
		return fmt.Errorf("baseline and target scan must be different")
	}
	if scan.Status != resource.ScanStatusComplete || baseline.Status != resource.ScanStatusComplete {
		return fmt.Errorf("baseline comparison requires two completed scans")
	}
	if scan.AccountID != baseline.AccountID {
		return fmt.Errorf("baseline and target scan must belong to the same AWS account")
	}
	regions := slices.Clone(scan.Regions)
	baselineRegions := slices.Clone(baseline.Regions)
	slices.Sort(regions)
	slices.Sort(baselineRegions)
	if !slices.Equal(slices.Compact(regions), slices.Compact(baselineRegions)) {
		return fmt.Errorf("baseline and target scan must cover the same regions")
	}
	return nil
}

// Match by rule and resource, ignoring changes to human-readable descriptions.
// Retain severity increases so a baseline cannot hide a worsening finding.
func newOrWorsenedFindings(current, baseline []findings.Finding) []findings.Finding {
	type key struct{ rule, resource string }
	previous := make(map[key]int, len(baseline))
	for _, f := range baseline {
		k := key{f.RuleID, f.ResourceID}
		rank := severityRank[f.Severity]
		if old, exists := previous[k]; !exists || rank > old {
			previous[k] = rank
		}
	}
	out := make([]findings.Finding, 0)
	for _, f := range current {
		if rank, exists := previous[key{f.RuleID, f.ResourceID}]; !exists || severityRank[f.Severity] > rank {
			out = append(out, f)
		}
	}
	return out
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
