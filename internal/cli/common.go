package cli

import (
	"context"
	"io"
	"os"

	"infralens/internal/findings"
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

var severityRank = map[findings.Severity]int{
	findings.SeverityInfo:   0,
	findings.SeverityLow:    1,
	findings.SeverityMedium: 2,
	findings.SeverityHigh:   3,
}

// filterBySeverity keeps findings at or above min. An unrecognized min
// value is treated as "info" (no filtering).
func filterBySeverity(fs []findings.Finding, min findings.Severity) []findings.Finding {
	threshold, ok := severityRank[min]
	if !ok {
		threshold = severityRank[findings.SeverityInfo]
	}
	var out []findings.Finding
	for _, f := range fs {
		if severityRank[f.Severity] >= threshold {
			out = append(out, f)
		}
	}
	return out
}
