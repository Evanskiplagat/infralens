package awsdiscovery

import (
	"context"
	"fmt"
)

// Options controls which account/region a Discoverer targets. Both
// fields are optional: the AWS SDK's standard credential and region
// resolution (environment, shared config, instance role, etc.) applies
// when they're left blank.
type Options struct {
	Profile string
	Region  string
}

// Discoverer collects one AWS service's resources into a shared
// Snapshot using only read-only API calls.
type Discoverer interface {
	Name() string
	Discover(ctx context.Context, opts Options, snap *Snapshot) error
}

// Run executes each discoverer in turn, aggregating their output into a
// single Snapshot. It stops at the first error so a scan never persists
// a silently partial result.
func Run(ctx context.Context, opts Options, discoverers []Discoverer) (*Snapshot, error) {
	snap := &Snapshot{}
	for _, d := range discoverers {
		if err := d.Discover(ctx, opts, snap); err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name(), err)
		}
	}
	return snap, nil
}
