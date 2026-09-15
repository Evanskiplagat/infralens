package cli

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"infralens/internal/findings"
	"infralens/internal/resource"
	"infralens/internal/storage/sqlite"
)

func TestNewOrWorsenedFindings(t *testing.T) {
	baseline := []findings.Finding{
		{RuleID: "open", ResourceID: "unchanged", Severity: findings.SeverityHigh, Title: "Old wording"},
		{RuleID: "open", ResourceID: "worse", Severity: findings.SeverityLow},
		{RuleID: "open", ResourceID: "better", Severity: findings.SeverityHigh},
		{RuleID: "open", ResourceID: "resolved", Severity: findings.SeverityHigh},
	}
	current := []findings.Finding{
		{RuleID: "open", ResourceID: "unchanged", Severity: findings.SeverityHigh, Title: "New wording"},
		{RuleID: "open", ResourceID: "worse", Severity: findings.SeverityHigh},
		{RuleID: "open", ResourceID: "better", Severity: findings.SeverityLow},
		{RuleID: "open", ResourceID: "new", Severity: findings.SeverityHigh},
		{RuleID: "other", ResourceID: "unchanged", Severity: findings.SeverityHigh},
	}
	want := []findings.Finding{current[1], current[3], current[4]}
	if got := newOrWorsenedFindings(current, baseline); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := newOrWorsenedFindings(current, nil); !reflect.DeepEqual(got, current) {
		t.Fatalf("empty baseline should retain all findings: %+v", got)
	}
	if got := filterBySeverity(newOrWorsenedFindings(baseline, baseline), findings.SeverityLow); got == nil || len(got) != 0 {
		t.Fatalf("no new findings should produce an empty JSON array, got %#v", got)
	}
}

func TestValidateBaseline(t *testing.T) {
	target := resource.Scan{ID: "target", AccountID: "123", Regions: []string{"b", "a"}, Status: resource.ScanStatusComplete}
	valid := resource.Scan{ID: "baseline", AccountID: "123", Regions: []string{"a", "b"}, Status: resource.ScanStatusComplete}
	if err := validateBaseline(target, valid); err != nil {
		t.Fatal(err)
	}
	if target.Regions[0] != "b" {
		t.Fatal("validation mutated the scan regions")
	}
	for _, name := range []string{"same scan", "account", "regions", "failed baseline", "running target"} {
		t.Run(name, func(t *testing.T) {
			scan, baseline := target, valid
			switch name {
			case "same scan":
				baseline.ID = scan.ID
			case "account":
				baseline.AccountID = "456"
			case "regions":
				baseline.Regions = []string{"a"}
			case "failed baseline":
				baseline.Status = resource.ScanStatusFailed
			case "running target":
				scan.Status = resource.ScanStatusRunning
			}
			if err := validateBaseline(scan, baseline); err == nil {
				t.Fatal("expected incompatible scans to be rejected")
			}
		})
	}
}

func TestRunFindingsBaselineGate(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "scans.db")
	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{"baseline", "target"} {
		scan := resource.Scan{ID: id, AccountID: "123", Regions: []string{"us-east-1"}, Status: resource.ScanStatusComplete, StartedAt: time.Now().UTC()}
		if err := store.CreateScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveFindings(ctx, id, []findings.Finding{{RuleID: "open", ResourceID: "existing", Severity: findings.SeverityHigh}}); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--db", dbPath, "--scan", "target", "--baseline", "baseline", "--fail-on", "medium", "--severity", "high", "--log-level", "error"}
	if err := runFindings(ctx, args); err != nil {
		t.Fatalf("existing findings should pass: %v", err)
	}
	if err := store.SaveFindings(ctx, "target", []findings.Finding{{RuleID: "open", ResourceID: "new", Severity: findings.SeverityMedium}}); err != nil {
		t.Fatal(err)
	}
	if err := runFindings(ctx, args); err == nil || !strings.Contains(err.Error(), "findings at or above medium") {
		t.Fatalf("new medium finding must fail even when display threshold is high: %v", err)
	}
	if err := runFindings(ctx, []string{"--db", dbPath, "--scan", "target", "--baseline", "missing"}); err == nil || !strings.Contains(err.Error(), "resolve baseline") {
		t.Fatalf("missing baseline should fail explicitly: %v", err)
	}
}
