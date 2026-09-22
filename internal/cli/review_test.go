package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"infralens/internal/awsdiscovery"
	"infralens/internal/findings"
	"infralens/internal/policy"
	"infralens/internal/resource"
)

var reviewNow = time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)

func mustPolicy(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return &p
}

func ids(fs []findings.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ResourceID)
	}
	return out
}

func TestReviewFindingsWithoutPolicyOrBaseline(t *testing.T) {
	in := []findings.Finding{{RuleID: "public_s3_bucket", ResourceID: "s3_bucket/a", Severity: findings.SeverityHigh}}
	rev := reviewFindings(in, nil, false, nil, reviewNow)
	if !reflect.DeepEqual(rev.found, in) || len(rev.suppressed) != 0 {
		t.Fatalf("review = %+v", rev)
	}
}

func TestReviewFindingsPolicyThenBaseline(t *testing.T) {
	pol := mustPolicy(t, `{
		"version": 1,
		"severity_overrides": {"default_vpc_in_use": "info"},
		"suppressions": [{"rule_id": "public_s3_bucket", "resource": "s3_bucket/site", "reason": "website"}]
	}`)
	baseline := []findings.Finding{
		{RuleID: "default_vpc_in_use", ResourceID: "vpc/v1", Severity: findings.SeverityLow},
		{RuleID: "open_security_group", ResourceID: "security_group/old", Severity: findings.SeverityMedium},
	}
	current := []findings.Finding{
		// Downgraded to info by policy on both sides, so it is not "worse".
		{RuleID: "default_vpc_in_use", ResourceID: "vpc/v1", Severity: findings.SeverityLow},
		// Existing finding, unchanged: hidden by the baseline.
		{RuleID: "open_security_group", ResourceID: "security_group/old", Severity: findings.SeverityMedium},
		// Waived by policy: never reported, but counted as suppressed.
		{RuleID: "public_s3_bucket", ResourceID: "s3_bucket/site", Severity: findings.SeverityHigh},
		// Genuinely new.
		{RuleID: "public_s3_bucket", ResourceID: "s3_bucket/new", Severity: findings.SeverityHigh},
	}

	rev := reviewFindings(current, baseline, true, pol, reviewNow)

	if got := ids(rev.found); !reflect.DeepEqual(got, []string{"s3_bucket/new"}) {
		t.Fatalf("only the new, unwaived finding should remain, got %v", got)
	}
	if len(rev.suppressed) != 1 || rev.suppressed[0].ResourceID != "s3_bucket/site" {
		t.Fatalf("suppressed = %+v", rev.suppressed)
	}
}

func TestReviewFindingsExpiredWaiverResurfacesAndIsReported(t *testing.T) {
	pol := mustPolicy(t, `{"version":1,"suppressions":[
		{"rule_id":"public_s3_bucket","resource":"s3_bucket/site","reason":"website","expires":"2026-09-20"}]}`)
	in := []findings.Finding{{RuleID: "public_s3_bucket", ResourceID: "s3_bucket/site", Severity: findings.SeverityHigh}}

	rev := reviewFindings(in, nil, false, pol, reviewNow)
	if len(rev.found) != 1 || len(rev.suppressed) != 0 {
		t.Fatalf("an expired waiver must not suppress: %+v", rev)
	}
	if len(rev.expired) != 1 || rev.expired[0].Expires != "2026-09-20" {
		t.Fatalf("expired waivers should be surfaced: %+v", rev.expired)
	}
}

func TestSeverityCriticalIsGateable(t *testing.T) {
	fs := []findings.Finding{
		{Severity: findings.SeverityCritical},
		{Severity: findings.SeverityHigh},
	}
	if got := filterBySeverity(fs, findings.SeverityCritical); len(got) != 1 {
		t.Fatalf("critical threshold should keep only critical findings: %+v", got)
	}
	if !shouldFailOnFindings(fs, findings.SeverityCritical) {
		t.Fatal("--fail-on critical should fail when a critical finding exists")
	}
	if severityRank[findings.SeverityCritical] <= severityRank[findings.SeverityHigh] {
		t.Fatal("critical must outrank high")
	}
}

func TestValidFindingsFormat(t *testing.T) {
	for _, ok := range []string{"table", "json", "sarif", "markdown"} {
		if !validFindingsFormat(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "xml", "csv", "SARIF"} {
		if validFindingsFormat(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestPrintFindingsTable(t *testing.T) {
	var buf bytes.Buffer
	printFindingsTable(&buf, "scan-1", nil, 2)
	out := buf.String()
	if !strings.Contains(out, "no findings for scan scan-1") || !strings.Contains(out, "2 finding(s) suppressed by policy") {
		t.Fatalf("output = %q", out)
	}

	buf.Reset()
	printFindingsTable(&buf, "scan-1", []findings.Finding{{Severity: findings.SeverityCritical, RuleID: "open_security_group", ResourceID: "security_group/sg-1"}}, 0)
	if !strings.Contains(buf.String(), "critical") || strings.Contains(buf.String(), "suppressed") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestParseRegions(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"us-east-1", []string{"us-east-1"}},
		{" us-east-1 , eu-west-1,,us-east-1 ", []string{"us-east-1", "eu-west-1"}},
		{",,", nil},
	}
	for _, tt := range tests {
		if got := parseRegions(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseRegions(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestScanOutcome(t *testing.T) {
	failure := awsdiscovery.Failure{Service: "ec2", Region: "eu-west-1", Attempts: 1, Err: errAny("denied")}

	status, msg := scanOutcome(awsdiscovery.Result{Tasks: 2, Succeeded: 2})
	if status != resource.ScanStatusComplete || msg != "" {
		t.Errorf("complete: %s %q", status, msg)
	}

	status, msg = scanOutcome(awsdiscovery.Result{Tasks: 2, Succeeded: 1, Failures: []awsdiscovery.Failure{failure}})
	if status != resource.ScanStatusPartial || !strings.Contains(msg, "eu-west-1") {
		t.Errorf("partial: %s %q", status, msg)
	}

	status, msg = scanOutcome(awsdiscovery.Result{Tasks: 1, Failures: []awsdiscovery.Failure{failure}})
	if status != resource.ScanStatusFailed || !strings.Contains(msg, "denied") {
		t.Errorf("failed: %s %q", status, msg)
	}
}

type errAny string

func (e errAny) Error() string { return string(e) }

func TestPartialScansAreNotValidBaselines(t *testing.T) {
	complete := resource.Scan{ID: "a", AccountID: "1", Regions: []string{"r"}, Status: resource.ScanStatusComplete}
	partial := resource.Scan{ID: "b", AccountID: "1", Regions: []string{"r"}, Status: resource.ScanStatusPartial}
	if err := validateBaseline(complete, partial); err == nil {
		t.Fatal("a partial baseline would make missing data look like fixed findings")
	}
	if err := validateBaseline(partial, complete); err == nil {
		t.Fatal("a partial target should not be diffed as if it were complete")
	}
}

func TestRulesCommand(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRules(&buf, nil); err != nil {
		t.Fatal(err)
	}
	for _, info := range findings.Catalog(findings.DefaultRules()) {
		if !strings.Contains(buf.String(), info.ID) {
			t.Errorf("rule list is missing %s", info.ID)
		}
	}

	buf.Reset()
	if err := writeRules(&buf, []string{"--id", "imdsv1_enabled"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"IMDSv1", "Remediation:", "Reference: https://"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("detail output missing %q:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	if err := writeRules(&buf, []string{"--format", "json"}); err != nil {
		t.Fatal(err)
	}
	var decoded []findings.RuleInfo
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil || len(decoded) != len(findings.DefaultRules()) {
		t.Fatalf("json output invalid: %v (%d rules)", err, len(decoded))
	}

	if err := writeRules(&buf, []string{"--id", "nope"}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("unknown rule error = %v", err)
	}
	if err := writeRules(&buf, []string{"--format", "yaml"}); err == nil {
		t.Fatal("unknown format should be rejected")
	}
}
