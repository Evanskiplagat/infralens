package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"infralens/internal/awsdiscovery"
	"infralens/internal/config"
	"infralens/internal/findings"
	"infralens/internal/graph"
	"infralens/internal/normalize"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func runScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	profile := fs.String("profile", "", "AWS profile to use (defaults to standard SDK resolution)")
	region := fs.String("region", "", "AWS region to scan (defaults to standard SDK resolution)")
	regionsFlag := fs.String("regions", "", "Comma-separated AWS regions to scan; overrides --region")
	concurrency := fs.Int("concurrency", awsdiscovery.DefaultConcurrency, "Maximum discovery tasks to run in parallel")
	maxAttempts := fs.Int("max-attempts", awsdiscovery.DefaultMaxAttempts, "Attempts per discovery task, including retries after throttling")
	allowPartial := fs.Bool("allow-partial", false, "Exit successfully even if some regions or services failed")
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 {
		return fmt.Errorf("--concurrency must be at least 1")
	}
	if *maxAttempts < 1 {
		return fmt.Errorf("--max-attempts must be at least 1")
	}

	cfg, logger, err := loadConfigWithLogger(config.Config{
		AWSProfile: *profile,
		AWSRegion:  *region,
		DBPath:     *dbPath,
		LogLevel:   *logLevel,
	})
	if err != nil {
		return err
	}

	regions := parseRegions(*regionsFlag)
	if len(regions) == 0 && cfg.AWSRegion != "" {
		regions = []string{cfg.AWSRegion}
	}
	opts := awsdiscovery.Options{Profile: cfg.AWSProfile}
	if len(regions) > 0 {
		opts.Region = regions[0]
	}

	// Resolve the account before creating the scan record so the scan is
	// stored with its account ID; baseline comparisons rely on it to refuse
	// comparing scans of different accounts. It is best-effort: a scan is
	// still useful without it, and real credential problems surface again
	// during discovery.
	accountID, err := awsdiscovery.CallerAccountID(ctx, opts)
	if err != nil {
		accountID = ""
		logger.Warnf("could not resolve caller account ID: %v", err)
	}

	logger.Infof("opening scan store at %s", cfg.DBPath)
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scan := resource.Scan{
		ID:        newScanID(),
		AccountID: accountID,
		Profile:   cfg.AWSProfile,
		Regions:   regions,
		StartedAt: time.Now().UTC(),
		Status:    resource.ScanStatusRunning,
	}
	if err := store.CreateScan(ctx, scan); err != nil {
		return fmt.Errorf("create scan record: %w", err)
	}
	logger.Infof("created scan %s", scan.ID)

	// Once the record exists, any failure must be reflected in it rather
	// than leaving a scan stuck in "running".
	abort := func(err error) error {
		_ = store.FinishScan(ctx, scan.ID, resource.ScanStatusFailed, err.Error())
		return err
	}

	discoverers := []awsdiscovery.Discoverer{awsdiscovery.EC2Discoverer{}, awsdiscovery.S3Discoverer{}}
	logger.Infof("starting discovery: %d service(s) across %s", len(discoverers), describeRegions(regions))
	result := awsdiscovery.Collect(ctx, opts, discoverers, awsdiscovery.Config{
		Regions:     regions,
		Concurrency: *concurrency,
		MaxAttempts: *maxAttempts,
		Logf:        logger.Infof,
	})
	for _, f := range result.Failures {
		logger.Errorf("discovery failed: %v", f)
	}
	for _, w := range result.Snapshot.Warnings {
		logger.Warnf("%s", w)
	}

	status, scanErr := scanOutcome(result)
	if status == resource.ScanStatusFailed {
		logger.Errorf("scan %s failed during discovery", scan.ID)
		return abort(fmt.Errorf("discover resources: %w", result.Err()))
	}

	resources, edges := normalize.Normalize(accountID, result.Snapshot)
	g := graph.Build(resources, edges)
	found := findings.Run(g, findings.DefaultRules())
	logger.Infof("discovered %d resources, %d edges, %d findings", len(resources), len(edges), len(found))

	if err := store.SaveResources(ctx, scan.ID, resources); err != nil {
		return abort(fmt.Errorf("save resources: %w", err))
	}
	if err := store.SaveEdges(ctx, scan.ID, edges); err != nil {
		return abort(fmt.Errorf("save edges: %w", err))
	}
	if err := store.SaveFindings(ctx, scan.ID, found); err != nil {
		return abort(fmt.Errorf("save findings: %w", err))
	}
	if err := store.FinishScan(ctx, scan.ID, status, scanErr); err != nil {
		return fmt.Errorf("finish scan: %w", err)
	}
	logger.Infof("scan %s finished with status %s", scan.ID, status)

	fmt.Printf("scan %s %s: %d resources, %d edges, %d findings\n", scan.ID, status, len(resources), len(edges), len(found))
	if status == resource.ScanStatusPartial && !*allowPartial {
		return fmt.Errorf("scan %s is partial: %d of %d discovery task(s) failed (the results were saved; rerun, or pass --allow-partial to accept them)",
			scan.ID, len(result.Failures), result.Tasks)
	}
	return nil
}

// scanOutcome decides how a finished discovery run is recorded: complete when
// every task succeeded, partial when some did, and failed when none did.
// The returned message is stored on the scan for later inspection.
func scanOutcome(r awsdiscovery.Result) (resource.ScanStatus, string) {
	switch {
	case r.Complete():
		return resource.ScanStatusComplete, ""
	case r.Partial():
		return resource.ScanStatusPartial, r.Err().Error()
	default:
		return resource.ScanStatusFailed, r.Err().Error()
	}
}

// parseRegions splits a comma-separated region list, trimming spaces and
// dropping blanks and duplicates while keeping the caller's order.
func parseRegions(raw string) []string {
	var regions []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		regions = append(regions, part)
	}
	return regions
}

func describeRegions(regions []string) string {
	if len(regions) == 0 {
		return "the default region"
	}
	return strings.Join(regions, ", ")
}

func newScanID() string {
	return time.Now().UTC().Format("20060102T150405Z")
}
