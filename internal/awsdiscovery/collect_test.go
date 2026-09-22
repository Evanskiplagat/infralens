package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDiscoverer is a scriptable Discoverer. It never touches AWS.
type fakeDiscoverer struct {
	name   string
	global bool
	// discover runs for every attempt; it may fill snap and return an error.
	discover func(ctx context.Context, opts Options, snap *Snapshot, attempt int) error

	mu       sync.Mutex
	attempts map[string]int // attempts per region
}

func (f *fakeDiscoverer) Name() string { return f.name }
func (f *fakeDiscoverer) Global() bool { return f.global }

func (f *fakeDiscoverer) Discover(ctx context.Context, opts Options, snap *Snapshot) error {
	f.mu.Lock()
	if f.attempts == nil {
		f.attempts = map[string]int{}
	}
	f.attempts[opts.Region]++
	attempt := f.attempts[opts.Region]
	f.mu.Unlock()
	return f.discover(ctx, opts, snap, attempt)
}

func (f *fakeDiscoverer) attemptsIn(region string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[region]
}

// regionVPC returns a discover func that records one VPC named after the region.
func regionVPC(err func(region string, attempt int) error) func(context.Context, Options, *Snapshot, int) error {
	return func(_ context.Context, opts Options, snap *Snapshot, attempt int) error {
		snap.VPCs = append(snap.VPCs, VPC{ID: "vpc-" + opts.Region, Region: opts.Region})
		if err != nil {
			return err(opts.Region, attempt)
		}
		return nil
	}
}

// codedError mimics an AWS SDK error, which exposes its code via ErrorCode().
type codedError struct{ code string }

func (e codedError) Error() string     { return "api error " + e.code }
func (e codedError) ErrorCode() string { return e.code }

// noSleep records requested delays without waiting.
type noSleep struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (n *noSleep) sleep(_ context.Context, d time.Duration) error {
	n.mu.Lock()
	n.delays = append(n.delays, d)
	n.mu.Unlock()
	return nil
}

func TestCollectFansOutAcrossRegionsInPlanOrder(t *testing.T) {
	ec2 := &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	res := Collect(context.Background(), Options{}, []Discoverer{ec2}, Config{
		Regions: []string{"us-east-1", "eu-west-1", "ap-south-1"},
	})

	if !res.Complete() || res.Tasks != 3 || res.Succeeded != 3 {
		t.Fatalf("result = %+v", res)
	}
	var ids []string
	for _, v := range res.Snapshot.VPCs {
		ids = append(ids, v.ID)
	}
	want := []string{"vpc-us-east-1", "vpc-eu-west-1", "vpc-ap-south-1"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("snapshot order = %v, want plan order %v", ids, want)
	}
}

func TestCollectIsDeterministicUnderConcurrency(t *testing.T) {
	regions := []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"}
	slowFirst := func(ctx context.Context, opts Options, snap *Snapshot, _ int) error {
		if opts.Region == "r1" {
			time.Sleep(20 * time.Millisecond) // finish out of order
		}
		snap.VPCs = append(snap.VPCs, VPC{ID: opts.Region})
		return nil
	}
	for i := 0; i < 5; i++ {
		res := Collect(context.Background(), Options{}, []Discoverer{&fakeDiscoverer{name: "ec2", discover: slowFirst}},
			Config{Regions: regions, Concurrency: 8})
		for j, v := range res.Snapshot.VPCs {
			if v.ID != regions[j] {
				t.Fatalf("run %d: position %d = %s, want %s", i, j, v.ID, regions[j])
			}
		}
	}
}

func TestCollectRunsGlobalDiscoverersOnce(t *testing.T) {
	regional := &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	global := &fakeDiscoverer{name: "s3", global: true, discover: func(_ context.Context, opts Options, snap *Snapshot, _ int) error {
		snap.S3Buckets = append(snap.S3Buckets, S3Bucket{Name: "bucket"})
		return nil
	}}
	res := Collect(context.Background(), Options{}, []Discoverer{regional, global},
		Config{Regions: []string{"us-east-1", "eu-west-1", "us-east-1"}}) // duplicate ignored

	if res.Tasks != 3 { // ec2 x2 regions + s3 x1
		t.Fatalf("tasks = %d, want 3", res.Tasks)
	}
	if len(res.Snapshot.S3Buckets) != 1 {
		t.Fatalf("global discoverer should contribute once, got %d buckets", len(res.Snapshot.S3Buckets))
	}
	if got := global.attemptsIn("us-east-1"); got != 1 {
		t.Fatalf("global discoverer should use the first region, attempts=%d", got)
	}
	if got := global.attemptsIn("eu-west-1"); got != 0 {
		t.Fatalf("global discoverer must not run for later regions, attempts=%d", got)
	}
}

func TestCollectDefaultsToOptionsRegion(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	res := Collect(context.Background(), Options{Region: "eu-north-1"}, []Discoverer{d}, Config{})
	if res.Tasks != 1 || d.attemptsIn("eu-north-1") != 1 {
		t.Fatalf("expected one task in the options region: %+v", res)
	}

	d = &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	res = Collect(context.Background(), Options{}, []Discoverer{d}, Config{})
	if res.Tasks != 1 || d.attemptsIn("") != 1 {
		t.Fatalf("with no region at all the SDK default (empty) should be used: %+v", res)
	}
}

func TestCollectBoundsConcurrency(t *testing.T) {
	var running, peak int32
	d := &fakeDiscoverer{name: "ec2", discover: func(ctx context.Context, opts Options, snap *Snapshot, _ int) error {
		n := atomic.AddInt32(&running, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		return nil
	}}
	regions := make([]string, 12)
	for i := range regions {
		regions[i] = fmt.Sprintf("r%d", i)
	}
	res := Collect(context.Background(), Options{}, []Discoverer{d}, Config{Regions: regions, Concurrency: 3})
	if !res.Complete() {
		t.Fatalf("unexpected failures: %v", res.Err())
	}
	if p := atomic.LoadInt32(&peak); p > 3 || p < 2 {
		t.Fatalf("peak concurrency = %d, want between 2 and 3", p)
	}
}

func TestCollectRetriesTransientErrorsWithBackoff(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(_ string, attempt int) error {
		if attempt < 3 {
			return codedError{"ThrottlingException"}
		}
		return nil
	})}
	sleeper := &noSleep{}
	res := Collect(context.Background(), Options{Region: "us-east-1"}, []Discoverer{d}, Config{
		MaxAttempts: 4, BaseBackoff: 100 * time.Millisecond, MaxBackoff: time.Second, Sleep: sleeper.sleep,
	})

	if !res.Complete() {
		t.Fatalf("throttled task should succeed after retries: %v", res.Err())
	}
	if d.attemptsIn("us-east-1") != 3 {
		t.Fatalf("attempts = %d, want 3", d.attemptsIn("us-east-1"))
	}
	if len(res.Snapshot.VPCs) != 1 {
		t.Fatalf("a retried task must not duplicate data from failed attempts: %+v", res.Snapshot.VPCs)
	}
	// Two waits: jittered into [50ms,100ms) then [100ms,200ms).
	if len(sleeper.delays) != 2 {
		t.Fatalf("delays = %v", sleeper.delays)
	}
	bounds := [][2]time.Duration{{50 * time.Millisecond, 100 * time.Millisecond}, {100 * time.Millisecond, 200 * time.Millisecond}}
	for i, d := range sleeper.delays {
		if d < bounds[i][0] || d >= bounds[i][1] {
			t.Errorf("delay %d = %v, want in [%v, %v)", i, d, bounds[i][0], bounds[i][1])
		}
	}
}

func TestCollectDoesNotRetryPermanentErrors(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(string, int) error {
		return codedError{"UnauthorizedOperation"}
	})}
	sleeper := &noSleep{}
	res := Collect(context.Background(), Options{Region: "us-east-1"}, []Discoverer{d}, Config{Sleep: sleeper.sleep})

	if d.attemptsIn("us-east-1") != 1 || len(sleeper.delays) != 0 {
		t.Fatalf("permission errors must fail immediately: attempts=%d delays=%v", d.attemptsIn("us-east-1"), sleeper.delays)
	}
	if len(res.Failures) != 1 || res.Failures[0].Attempts != 1 {
		t.Fatalf("failures = %+v", res.Failures)
	}
}

func TestCollectGivesUpAfterMaxAttempts(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(string, int) error { return codedError{"RequestLimitExceeded"} })}
	res := Collect(context.Background(), Options{Region: "us-east-1"}, []Discoverer{d}, Config{
		MaxAttempts: 3, Sleep: (&noSleep{}).sleep,
	})
	if d.attemptsIn("us-east-1") != 3 || len(res.Failures) != 1 || res.Failures[0].Attempts != 3 {
		t.Fatalf("attempts=%d failures=%+v", d.attemptsIn("us-east-1"), res.Failures)
	}
	if len(res.Snapshot.VPCs) != 0 {
		t.Fatalf("a failed task must contribute no data: %+v", res.Snapshot.VPCs)
	}
}

func TestCollectKeepsPartialResultsWhenOneRegionFails(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(region string, _ int) error {
		if region == "eu-west-1" {
			return codedError{"AuthFailure"}
		}
		return nil
	})}
	res := Collect(context.Background(), Options{}, []Discoverer{d}, Config{
		Regions: []string{"us-east-1", "eu-west-1", "ap-south-1"},
	})

	if !res.Partial() || res.Complete() {
		t.Fatalf("want a partial result, got %+v", res)
	}
	if res.Succeeded != 2 || len(res.Failures) != 1 {
		t.Fatalf("succeeded=%d failures=%d", res.Succeeded, len(res.Failures))
	}
	f := res.Failures[0]
	if f.Service != "ec2" || f.Region != "eu-west-1" {
		t.Fatalf("failure = %+v", f)
	}
	if len(res.Snapshot.VPCs) != 2 {
		t.Fatalf("successful regions must be kept: %+v", res.Snapshot.VPCs)
	}
	err := res.Err()
	if err == nil || !strings.Contains(err.Error(), "eu-west-1") || !strings.Contains(err.Error(), "AuthFailure") {
		t.Fatalf("Err() = %v", err)
	}
	var coded interface{ ErrorCode() string }
	if !errors.As(err, &coded) || coded.ErrorCode() != "AuthFailure" {
		t.Fatal("Err() must keep the underlying error reachable with errors.As")
	}
}

func TestCollectAllFailed(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(string, int) error { return errors.New("boom") })}
	res := Collect(context.Background(), Options{}, []Discoverer{d}, Config{Regions: []string{"a", "b"}})
	if res.Partial() || res.Complete() || res.Succeeded != 0 || len(res.Failures) != 2 {
		t.Fatalf("result = %+v", res)
	}
}

func TestCollectRecoversFromPanics(t *testing.T) {
	bad := &fakeDiscoverer{name: "bad", discover: func(context.Context, Options, *Snapshot, int) error { panic("kaboom") }}
	good := &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	res := Collect(context.Background(), Options{Region: "us-east-1"}, []Discoverer{bad, good}, Config{})
	if !res.Partial() || len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "kaboom") {
		t.Fatalf("a panic should become a failure without stopping other tasks: %+v", res)
	}
	if len(res.Snapshot.VPCs) != 1 {
		t.Fatal("the healthy discoverer's data should survive")
	}
}

func TestCollectStopsWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	d := &fakeDiscoverer{name: "ec2", discover: func(ctx context.Context, _ Options, _ *Snapshot, _ int) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	go func() { <-started; cancel() }()

	done := make(chan Result, 1)
	go func() { done <- Collect(ctx, Options{Region: "us-east-1"}, []Discoverer{d}, Config{MaxAttempts: 5}) }()

	select {
	case res := <-done:
		if len(res.Failures) != 1 || !errors.Is(res.Failures[0].Err, context.Canceled) {
			t.Fatalf("failures = %+v", res.Failures)
		}
		if res.Failures[0].Attempts != 1 {
			t.Fatalf("a cancelled scan must not keep retrying, attempts=%d", res.Failures[0].Attempts)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Collect did not return after cancellation")
	}
}

func TestCollectCancelledDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(func(string, int) error { return codedError{"Throttling"} })}
	res := Collect(ctx, Options{Region: "us-east-1"}, []Discoverer{d}, Config{
		MaxAttempts: 5,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			cancel()
			return ctx.Err()
		},
	})
	if len(res.Failures) != 1 || d.attemptsIn("us-east-1") != 1 {
		t.Fatalf("attempts=%d failures=%+v", d.attemptsIn("us-east-1"), res.Failures)
	}
	if !strings.Contains(res.Failures[0].Err.Error(), "retry cancelled") {
		t.Fatalf("error should explain the cancelled retry: %v", res.Failures[0].Err)
	}
}

func TestCollectWithNoDiscoverers(t *testing.T) {
	res := Collect(context.Background(), Options{}, nil, Config{})
	if res.Tasks != 0 || !res.Complete() || res.Snapshot == nil {
		t.Fatalf("result = %+v", res)
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{codedError{"Throttling"}, true},
		{codedError{"ThrottlingException"}, true},
		{codedError{"RequestLimitExceeded"}, true},
		{codedError{"ServiceUnavailable"}, true},
		{codedError{"UnauthorizedOperation"}, false},
		{codedError{"InvalidParameterValue"}, false},
		{fmt.Errorf("describe vpcs: %w", codedError{"RequestLimitExceeded"}), true},
		{context.Canceled, false},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), true},
		{errors.New("plain failure"), false},
	}
	for _, tt := range tests {
		if got := IsTransient(tt.err); got != tt.want {
			t.Errorf("IsTransient(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestIsAccessDenied(t *testing.T) {
	for _, code := range []string{"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"} {
		if !IsAccessDenied(fmt.Errorf("describe volumes: %w", codedError{code})) {
			t.Errorf("%s should be treated as access denied", code)
		}
	}
	for _, err := range []error{nil, errors.New("plain"), codedError{"Throttling"}, codedError{"InvalidParameterValue"}} {
		if IsAccessDenied(err) {
			t.Errorf("%v should not be access denied", err)
		}
	}
}

func TestCollectMergesWarnings(t *testing.T) {
	warn := func(msg string) func(context.Context, Options, *Snapshot, int) error {
		return func(_ context.Context, opts Options, snap *Snapshot, _ int) error {
			snap.Warnings = append(snap.Warnings, msg+" in "+opts.Region)
			return nil
		}
	}
	res := Collect(context.Background(), Options{}, []Discoverer{&fakeDiscoverer{name: "ec2", discover: warn("skipped volumes")}},
		Config{Regions: []string{"a", "b"}})
	want := []string{"skipped volumes in a", "skipped volumes in b"}
	if !reflect.DeepEqual(res.Snapshot.Warnings, want) {
		t.Fatalf("warnings = %v, want %v", res.Snapshot.Warnings, want)
	}
	if !res.Complete() {
		t.Fatal("warnings about optional data must not make a scan partial")
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	base, ceiling := 100*time.Millisecond, 400*time.Millisecond
	for attempt, wantMax := range map[int]time.Duration{1: 100 * time.Millisecond, 2: 200 * time.Millisecond, 3: 400 * time.Millisecond, 9: 400 * time.Millisecond} {
		for i := 0; i < 50; i++ {
			d := backoff(attempt, base, ceiling)
			if d < wantMax/2 || d >= wantMax {
				t.Fatalf("backoff(attempt %d) = %v, want in [%v, %v)", attempt, d, wantMax/2, wantMax)
			}
		}
	}
	if d := backoff(1, 0, 0); d != 0 {
		t.Fatalf("zero durations should not panic or wait, got %v", d)
	}
}

func TestFailureError(t *testing.T) {
	f := Failure{Service: "ec2", Region: "", Attempts: 2, Err: errors.New("denied")}
	if got := f.Error(); got != "ec2 in default region (after 2 attempt(s)): denied" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestSnapshotMergeCoversEveryField(t *testing.T) {
	// Guards against adding a Snapshot slice and forgetting to merge it, which
	// would silently drop that resource type from every multi-task scan.
	other := &Snapshot{}
	v := reflect.ValueOf(other).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Slice {
			t.Fatalf("Snapshot field %s is not a slice; update Merge and this test", v.Type().Field(i).Name)
		}
		f.Set(reflect.MakeSlice(f.Type(), 1, 1))
	}

	merged := &Snapshot{}
	merged.Merge(other)
	merged.Merge(other)
	m := reflect.ValueOf(merged).Elem()
	for i := 0; i < m.NumField(); i++ {
		if got := m.Field(i).Len(); got != 2 {
			t.Errorf("Merge dropped %s: len = %d, want 2", m.Type().Field(i).Name, got)
		}
	}
	merged.Merge(nil) // must not panic
}

func TestPlanNormalizesRegions(t *testing.T) {
	d := &fakeDiscoverer{name: "ec2", discover: regionVPC(nil)}
	tasks := plan(Options{Profile: "dev"}, []Discoverer{d}, []string{" us-east-1 ", "", "eu-west-1", "us-east-1"})
	if len(tasks) != 2 || tasks[0].opts.Region != "us-east-1" || tasks[1].opts.Region != "eu-west-1" {
		t.Fatalf("tasks = %+v", tasks)
	}
	if tasks[0].opts.Profile != "dev" {
		t.Fatal("tasks must inherit the profile")
	}
}
