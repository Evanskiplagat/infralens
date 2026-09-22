package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"infralens/internal/config"
	"infralens/internal/export"
	"infralens/internal/findings"
	"infralens/internal/policy"
	"infralens/internal/report"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

// now is the clock used to evaluate waiver expiry and stamp reports. Tests
// replace it so expiry behavior does not depend on the day they run.
var now = time.Now

const findingsFormats = "table, json, sarif, or markdown"

func runFindings(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	scanID := fs.String("scan", "latest", `Scan ID to load, or "latest"`)
	baselineID := fs.String("baseline", "", "Completed scan ID to compare against; include only new or worsened findings")
	format := fs.String("format", "table", "Output format: "+findingsFormats)
	minSeverity := fs.String("severity", "low", "Minimum severity to include: info, low, medium, high, critical")
	failOn := fs.String("fail-on", "", "Exit non-zero if any finding at or above this severity exists: info, low, medium, high, critical")
	policyPath := fs.String("policy", "", "Path to a policy file that disables rules, overrides severities, and waives findings")
	out := fs.String("out", "", "Write output to a file instead of stdout")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !validFindingsFormat(*format) {
		return fmt.Errorf("unknown format %q (want %s)", *format, findingsFormats)
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

	// Load the policy before touching the database so a malformed policy
	// fails fast, before any output is produced.
	var pol *policy.Policy
	if *policyPath != "" {
		loaded, err := policy.Load(*policyPath)
		if err != nil {
			return err
		}
		pol = &loaded
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
	if scan.Status == resource.ScanStatusPartial {
		logger.Warnf("scan %s is partial (%s); findings may be incomplete", scan.ID, scan.Error)
	}

	found, err := store.LoadFindings(ctx, scan.ID)
	if err != nil {
		return err
	}

	var previous []findings.Finding
	if *baselineID != "" {
		baseline, err := store.GetScan(ctx, *baselineID)
		if err != nil {
			return fmt.Errorf("resolve baseline scan: %w", err)
		}
		if err := validateBaseline(scan, baseline); err != nil {
			return err
		}
		previous, err = store.LoadFindings(ctx, baseline.ID)
		if err != nil {
			return fmt.Errorf("load baseline findings: %w", err)
		}
	}

	rev := reviewFindings(found, previous, *baselineID != "", pol, now())
	for _, w := range rev.expired {
		logger.Warnf("policy waiver for %s on %s expired on %s; its findings are reported again", w.RuleID, w.Resource, w.Expires)
	}
	for _, w := range rev.unmatched {
		logger.Warnf("policy waiver for %s on %s matched no findings and can be removed", w.RuleID, w.Resource)
	}
	found, suppressed := rev.found, rev.suppressed
	fail := shouldFailOnFindings(found, failThreshold)
	found = filterBySeverity(found, threshold)

	w, closeFn, err := openOutput(*out)
	if err != nil {
		return err
	}
	defer closeFn()

	switch *format {
	case "json":
		if err := export.WriteJSON(w, found); err != nil {
			return err
		}
	case "table":
		printFindingsTable(w, scan.ID, found, len(suppressed))
	case "sarif", "markdown":
		input := report.Input{
			Meta: report.Meta{
				ScanID:      scan.ID,
				AccountID:   scan.AccountID,
				Regions:     scan.Regions,
				Status:      string(scan.Status),
				ToolVersion: Version,
				GeneratedAt: now(),
			},
			Findings:   found,
			Suppressed: suppressed,
			Rules:      findings.Catalog(findings.DefaultRules()),
		}
		write := report.WriteSARIF
		if *format == "markdown" {
			write = report.WriteMarkdown
		}
		if err := write(w, input); err != nil {
			return err
		}
	}

	if fail {
		return fmt.Errorf("findings at or above %s severity detected", failThreshold)
	}
	return nil
}

// review is the outcome of applying a policy and a baseline to a scan's
// findings.
type review struct {
	found      []findings.Finding
	suppressed []findings.Suppressed
	expired    []policy.Suppression
	unmatched  []policy.Suppression
}

// reviewFindings narrows a scan's findings to what needs attention. The
// policy runs first, on both the target and the baseline, so that a severity
// override or waiver is judged identically on each side of the comparison
// instead of showing up as a spurious "new" finding. When useBaseline is set,
// only findings that are new or worse than in the baseline remain.
func reviewFindings(current, baseline []findings.Finding, useBaseline bool, pol *policy.Policy, at time.Time) review {
	rev := review{found: current}
	if pol != nil {
		evaluated := pol.Apply(current, at)
		rev.found = evaluated.Kept
		rev.suppressed = evaluated.Suppressed
		rev.expired = evaluated.Expired
		rev.unmatched = evaluated.Unmatched
		if useBaseline {
			baseline = pol.Apply(baseline, at).Kept
		}
	}
	if useBaseline {
		rev.found = newOrWorsenedFindings(rev.found, baseline)
	}
	return rev
}

func validFindingsFormat(format string) bool {
	switch format {
	case "table", "json", "sarif", "markdown":
		return true
	}
	return false
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

func printFindingsTable(w io.Writer, scanID string, found []findings.Finding, suppressed int) {
	if len(found) == 0 {
		fmt.Fprintf(w, "no findings for scan %s\n", scanID)
	} else {
		fmt.Fprintf(w, "%-10s %-32s %-40s\n", "SEVERITY", "RULE", "RESOURCE")
		for _, f := range found {
			fmt.Fprintf(w, "%-10s %-32s %-40s\n", f.Severity, f.RuleID, f.ResourceID)
		}
	}
	if suppressed > 0 {
		fmt.Fprintf(w, "\n%d finding(s) suppressed by policy\n", suppressed)
	}
}
