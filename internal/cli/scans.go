package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"infralens/internal/config"
	"infralens/internal/storage/sqlite"
)

func runScans(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scans", flag.ContinueOnError)
	dbPath := fs.String("db", "", "Path to the InfraLens SQLite database")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, logger, err := loadConfigWithLogger(config.Config{DBPath: *dbPath, LogLevel: *logLevel})
	if err != nil {
		return err
	}
	logger.Debugf("opening scans store at %s", cfg.DBPath)
	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	scans, err := store.ListScans(ctx)
	if err != nil {
		return err
	}

	if len(scans) == 0 {
		fmt.Println("no scans found; run `infralens scan` first")
		return nil
	}

	fmt.Printf("%-18s %-10s %-25s %-20s\n", "ID", "STATUS", "STARTED", "REGIONS")
	for _, s := range scans {
		fmt.Printf("%-18s %-10s %-25s %-20s\n", s.ID, s.Status, s.StartedAt.Format(time.RFC3339), strings.Join(s.Regions, ","))
	}
	return nil
}
