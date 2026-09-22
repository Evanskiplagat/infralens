package resource

import "time"

// ScanStatus tracks the lifecycle of a scan record.
type ScanStatus string

const (
	ScanStatusRunning  ScanStatus = "running"
	ScanStatusComplete ScanStatus = "complete"
	ScanStatusFailed   ScanStatus = "failed"
	// ScanStatusPartial marks a scan where at least one discovery task
	// succeeded and at least one failed. Its resources and findings are
	// stored, but it is not a valid baseline for comparisons because
	// missing data would look like remediated infrastructure.
	ScanStatusPartial ScanStatus = "partial"
)

// Scan is the metadata record for a single discovery run. Resources,
// edges, and findings are all stored keyed by Scan.ID.
type Scan struct {
	ID         string
	AccountID  string
	Profile    string
	Regions    []string
	StartedAt  time.Time
	FinishedAt time.Time
	Status     ScanStatus
	Error      string
}
