// Package storage defines the persistence boundary between InfraLens's
// domain packages and whatever database backs a scan history. The Store
// interface is the contract every command depends on; internal/storage
// exists so a future PostgreSQL implementation can sit next to the
// SQLite one without touching the CLI or domain packages.
package storage

import (
	"context"

	"infralens/internal/findings"
	"infralens/internal/resource"
)

// Store persists scans and their discovered resources, edges, and
// findings. Implementations are expected to be safe for a single CLI
// invocation; concurrent access from multiple processes is not required.
type Store interface {
	CreateScan(ctx context.Context, scan resource.Scan) error
	FinishScan(ctx context.Context, scanID string, status resource.ScanStatus, scanErr string) error

	SaveResources(ctx context.Context, scanID string, resources []resource.Resource) error
	SaveEdges(ctx context.Context, scanID string, edges []resource.Edge) error
	SaveFindings(ctx context.Context, scanID string, findings []findings.Finding) error

	GetScan(ctx context.Context, scanID string) (resource.Scan, error)
	LatestScan(ctx context.Context) (resource.Scan, error)
	ListScans(ctx context.Context) ([]resource.Scan, error)

	LoadResources(ctx context.Context, scanID string) ([]resource.Resource, error)
	LoadEdges(ctx context.Context, scanID string) ([]resource.Edge, error)
	LoadFindings(ctx context.Context, scanID string) ([]findings.Finding, error)

	Close() error
}
