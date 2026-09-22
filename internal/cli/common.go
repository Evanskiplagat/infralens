package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"infralens/internal/config"
	"infralens/internal/findings"
	"infralens/internal/logging"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

// resolveScan looks up a scan by ID, treating "" and "latest" as a
// request for the most recently started scan.
func resolveScan(ctx context.Context, store *sqlite.Store, id string) (resource.Scan, error) {
	if id == "" || id == "latest" {
		return store.LatestScan(ctx)
	}
	return store.GetScan(ctx, id)
}

// openOutput returns stdout when path is empty, otherwise a newly
// created file at path. The returned close func is always safe to call.
func openOutput(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// severityRank is derived from the findings package so the CLI can never
// disagree with the rules about what "at or above" means.
var severityRank = func() map[findings.Severity]int {
	ranks := make(map[findings.Severity]int)
	for _, s := range findings.AllSeverities() {
		ranks[s] = s.Rank()
	}
	return ranks
}()

// filterBySeverity keeps findings at or above min. An unrecognized min
// value is treated as "info" (no filtering).
func filterBySeverity(fs []findings.Finding, min findings.Severity) []findings.Finding {
	threshold, ok := severityRank[min]
	if !ok {
		threshold = severityRank[findings.SeverityInfo]
	}
	out := make([]findings.Finding, 0)
	for _, f := range fs {
		if severityRank[f.Severity] >= threshold {
			out = append(out, f)
		}
	}
	return out
}

func parseSeverity(raw string) (findings.Severity, error) {
	severity := findings.Severity(raw)
	if _, ok := severityRank[severity]; !ok {
		return "", fmt.Errorf("unknown severity %q (want info, low, medium, high, or critical)", raw)
	}
	return severity, nil
}

func shouldFailOnFindings(fs []findings.Finding, failOn findings.Severity) bool {
	if failOn == "" {
		return false
	}
	return len(filterBySeverity(fs, failOn)) > 0
}

func loadConfigWithLogger(overrides config.Config) (config.Config, logging.Logger, error) {
	cfg, err := config.Load(overrides)
	if err != nil {
		return config.Config{}, logging.Logger{}, err
	}
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		return config.Config{}, logging.Logger{}, err
	}
	return cfg, logger, nil
}
