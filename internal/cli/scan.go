package cli

import (
	"context"
	"flag"
	"fmt"
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
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(config.Config{AWSProfile: *profile, AWSRegion: *region, DBPath: *dbPath})
	if err != nil {
		return err
	}

	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scan := resource.Scan{
		ID:        newScanID(),
		Profile:   cfg.AWSProfile,
		StartedAt: time.Now().UTC(),
		Status:    resource.ScanStatusRunning,
	}
	if cfg.AWSRegion != "" {
		scan.Regions = []string{cfg.AWSRegion}
	}
	if err := store.CreateScan(ctx, scan); err != nil {
		return fmt.Errorf("create scan record: %w", err)
	}

	opts := awsdiscovery.Options{Profile: cfg.AWSProfile, Region: cfg.AWSRegion}
	discoverers := []awsdiscovery.Discoverer{awsdiscovery.EC2Discoverer{}, awsdiscovery.S3Discoverer{}}

	snap, err := awsdiscovery.Run(ctx, opts, discoverers)
	if err != nil {
		_ = store.FinishScan(ctx, scan.ID, resource.ScanStatusFailed, err.Error())
		return fmt.Errorf("discover resources: %w", err)
	}

	accountID, err := awsdiscovery.CallerAccountID(ctx, opts)
	if err != nil {
		accountID = "" // account tagging is best-effort; a scan is still useful without it
	}

	resources, edges := normalize.Normalize(accountID, snap)
	g := graph.Build(resources, edges)
	found := findings.Run(g, findings.DefaultRules())

	if err := store.SaveResources(ctx, scan.ID, resources); err != nil {
		return fmt.Errorf("save resources: %w", err)
	}
	if err := store.SaveEdges(ctx, scan.ID, edges); err != nil {
		return fmt.Errorf("save edges: %w", err)
	}
	if err := store.SaveFindings(ctx, scan.ID, found); err != nil {
		return fmt.Errorf("save findings: %w", err)
	}
	if err := store.FinishScan(ctx, scan.ID, resource.ScanStatusComplete, ""); err != nil {
		return fmt.Errorf("finish scan: %w", err)
	}

	fmt.Printf("scan %s complete: %d resources, %d edges, %d findings\n", scan.ID, len(resources), len(edges), len(found))
	return nil
}

func newScanID() string {
	return time.Now().UTC().Format("20060102T150405Z")
}
