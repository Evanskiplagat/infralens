package resource

import "time"

// ScanStatus tracks the lifecycle of a scan record.
type ScanStatus string

const (
	ScanStatusRunning  ScanStatus = "running"
	ScanStatusComplete ScanStatus = "complete"
	ScanStatusFailed   ScanStatus = "failed"
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
