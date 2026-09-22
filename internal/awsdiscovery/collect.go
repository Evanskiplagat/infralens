package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"
)

// Defaults for Config zero values.
const (
	DefaultConcurrency = 4
	DefaultMaxAttempts = 3
	DefaultBaseBackoff = 500 * time.Millisecond
	DefaultMaxBackoff  = 20 * time.Second
)

// Global is implemented by discoverers for services that are not regional
// (S3 bucket listing, for example). A global discoverer runs once per scan
// instead of once per region.
type Global interface {
	Global() bool
}

func isGlobal(d Discoverer) bool {
	g, ok := d.(Global)
	return ok && g.Global()
}

// Config controls how Collect fans discovery out across regions and services.
// The zero value is usable: one region (from Options), DefaultConcurrency
// workers, and DefaultMaxAttempts attempts per task.
type Config struct {
	// Regions to scan. Empty means the single region in Options (which may
	// itself be empty, deferring to the AWS SDK's own resolution).
	Regions []string
	// Concurrency bounds how many discovery tasks run at once.
	Concurrency int
	// MaxAttempts is the total number of tries per task, including the first.
	MaxAttempts int
	// BaseBackoff and MaxBackoff shape the exponential delay between tries.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Retryable decides whether a failed attempt is worth repeating. The
	// default retries throttling and transient service errors only, never
	// permission or validation errors that would fail identically again.
	Retryable func(error) bool
	// Logf receives progress messages. It may be nil.
	Logf func(format string, args ...any)
	// Sleep waits between retries and returns early with the context's error
	// if it is cancelled. Tests replace it; the default uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Failure records one discovery task that did not succeed.
type Failure struct {
	Service  string
	Region   string
	Attempts int
	Err      error
}

func (f Failure) Error() string {
	region := f.Region
	if region == "" {
		region = "default region"
	}
	return fmt.Sprintf("%s in %s (after %d attempt(s)): %v", f.Service, region, f.Attempts, f.Err)
}

func (f Failure) Unwrap() error { return f.Err }

// Result is what a Collect run produced. Snapshot holds everything the
// successful tasks discovered even when others failed, so callers can decide
// whether a partial scan is acceptable instead of losing all the work.
type Result struct {
	Snapshot  *Snapshot
	Tasks     int
	Succeeded int
	Failures  []Failure
}

// Complete reports whether every task succeeded.
func (r Result) Complete() bool { return len(r.Failures) == 0 }

// Partial reports whether some, but not all, tasks succeeded.
func (r Result) Partial() bool { return len(r.Failures) > 0 && r.Succeeded > 0 }

// Err summarizes every failure as one error, or nil when all tasks succeeded.
func (r Result) Err() error {
	if len(r.Failures) == 0 {
		return nil
	}
	errs := make([]error, len(r.Failures))
	for i, f := range r.Failures {
		errs[i] = f
	}
	return errors.Join(errs...)
}

type task struct {
	discoverer Discoverer
	opts       Options
}

// plan expands discoverers and regions into tasks in a fixed order: by
// region as given, then by discoverer. Global discoverers appear once, with
// the first region's credentials context.
func plan(opts Options, discoverers []Discoverer, regions []string) []task {
	regions = normalizeRegions(regions)
	if len(regions) == 0 {
		regions = []string{opts.Region}
	}
	var tasks []task
	for i, region := range regions {
		for _, d := range discoverers {
			if isGlobal(d) && i > 0 {
				continue
			}
			taskOpts := opts
			taskOpts.Region = region
			tasks = append(tasks, task{discoverer: d, opts: taskOpts})
		}
	}
	return tasks
}

// normalizeRegions trims, drops blanks and removes duplicates, keeping the
// caller's order.
func normalizeRegions(regions []string) []string {
	seen := make(map[string]bool, len(regions))
	out := make([]string, 0, len(regions))
	for _, r := range regions {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

type outcome struct {
	snapshot *Snapshot
	attempts int
	err      error
}

// Collect runs every discoverer against every configured region with bounded
// concurrency, retrying transient failures with exponential backoff and
// jitter. A task that ultimately fails is recorded in Result.Failures while
// the rest carry on, so one denied region does not discard a whole scan.
//
// Each task fills its own Snapshot, which are merged afterwards in plan
// order; the merged result is identical no matter how tasks were scheduled.
func Collect(ctx context.Context, opts Options, discoverers []Discoverer, cfg Config) Result {
	cfg = cfg.withDefaults()
	tasks := plan(opts, discoverers, cfg.Regions)
	outcomes := make([]outcome, len(tasks))

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		go func(i int, t task) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				outcomes[i] = outcome{err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			outcomes[i] = runTask(ctx, t, cfg)
		}(i, t)
	}
	wg.Wait()

	res := Result{Snapshot: &Snapshot{}, Tasks: len(tasks)}
	for i, o := range outcomes {
		if o.err != nil {
			res.Failures = append(res.Failures, Failure{
				Service:  tasks[i].discoverer.Name(),
				Region:   tasks[i].opts.Region,
				Attempts: o.attempts,
				Err:      o.err,
			})
			continue
		}
		res.Succeeded++
		res.Snapshot.Merge(o.snapshot)
	}
	return res
}

func (c Config) withDefaults() Config {
	if c.Concurrency < 1 {
		c.Concurrency = DefaultConcurrency
	}
	if c.MaxAttempts < 1 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = DefaultBaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.Retryable == nil {
		c.Retryable = IsTransient
	}
	if c.Sleep == nil {
		c.Sleep = sleepContext
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

func runTask(ctx context.Context, t task, cfg Config) outcome {
	name := t.discoverer.Name()
	region := t.opts.Region
	if region == "" {
		region = "default region"
	}

	var last outcome
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		snap, err := discoverOnce(ctx, t)
		if err == nil {
			cfg.Logf("discovered %s in %s (attempt %d)", name, region, attempt)
			return outcome{snapshot: snap, attempts: attempt}
		}
		last = outcome{attempts: attempt, err: err}

		if attempt == cfg.MaxAttempts || ctx.Err() != nil || !cfg.Retryable(err) {
			break
		}
		delay := backoff(attempt, cfg.BaseBackoff, cfg.MaxBackoff)
		cfg.Logf("%s in %s failed (attempt %d of %d): %v; retrying in %s",
			name, region, attempt, cfg.MaxAttempts, err, delay.Round(time.Millisecond))
		if err := cfg.Sleep(ctx, delay); err != nil {
			last.err = fmt.Errorf("%w (retry cancelled: %v)", last.err, err)
			break
		}
	}
	cfg.Logf("%s in %s failed: %v", name, region, last.err)
	return last
}

// discoverOnce runs a single attempt into a fresh Snapshot, so a retry never
// duplicates what an earlier partial attempt already appended. A panicking
// discoverer becomes an error rather than taking down the whole scan.
func discoverOnce(ctx context.Context, t task) (snap *Snapshot, err error) {
	defer func() {
		if r := recover(); r != nil {
			snap, err = nil, fmt.Errorf("discoverer panicked: %v", r)
		}
	}()
	snap = &Snapshot{}
	if err := t.discoverer.Discover(ctx, t.opts, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// backoff returns the delay before retry number attempt (1-based): base
// doubled per attempt, capped at ceiling, then jittered into [d/2, d) so many
// tasks that were throttled together do not retry in lockstep.
func backoff(attempt int, base, ceiling time.Duration) time.Duration {
	d := base
	for i := 1; i < attempt && d < ceiling; i++ {
		d *= 2
	}
	if d > ceiling {
		d = ceiling
	}
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(rand.Int64N(int64(half)))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// transientCodes are AWS API error codes that indicate throttling or a
// temporary service problem. The AWS SDK already retries most of these
// internally; this outer layer covers the ones that still surface after the
// SDK gives up, notably during bursts across many regions.
var transientCodes = map[string]bool{
	"Throttling":                             true,
	"ThrottlingException":                    true,
	"ThrottledException":                     true,
	"RequestThrottled":                       true,
	"RequestLimitExceeded":                   true,
	"TooManyRequestsException":               true,
	"ProvisionedThroughputExceededException": true,
	"SlowDown":                               true,
	"RequestTimeout":                         true,
	"RequestTimeoutException":                true,
	"ServiceUnavailable":                     true,
	"InternalError":                          true,
	"InternalFailure":                        true,
}

// accessDeniedCodes are AWS API error codes for a permission failure. EC2
// reports UnauthorizedOperation; most other services use AccessDenied.
var accessDeniedCodes = map[string]bool{
	"UnauthorizedOperation": true,
	"AccessDenied":          true,
	"AccessDeniedException": true,
}

// IsAccessDenied reports whether err is an AWS permission failure, matched by
// the ErrorCode() method AWS SDK errors implement.
func IsAccessDenied(err error) bool {
	var coded interface{ ErrorCode() string }
	return errors.As(err, &coded) && accessDeniedCodes[coded.ErrorCode()]
}

// IsTransient reports whether err looks like throttling, a timeout, or a
// temporary service fault that is worth retrying. Errors are matched by the
// ErrorCode() method AWS SDK errors implement, so this package does not need
// to import the SDK's error types.
func IsTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var coded interface{ ErrorCode() string }
	if errors.As(err, &coded) {
		return transientCodes[coded.ErrorCode()]
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}
