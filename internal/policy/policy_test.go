package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"infralens/internal/findings"
)

var now = time.Date(2026, time.September, 21, 10, 30, 0, 0, time.UTC)

func finding(rule, resource string, sev findings.Severity) findings.Finding {
	return findings.Finding{RuleID: rule, ResourceID: resource, Severity: sev, Title: rule + " on " + resource}
}

func mustParse(t *testing.T, doc string) Policy {
	t.Helper()
	p, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "", true},
		{"*", "s3_bucket/anything", true},
		{"s3_bucket/site-*", "s3_bucket/site-assets", true},
		{"s3_bucket/site-*", "s3_bucket/other", false},
		{"*/i-123", "ec2_instance/i-123", true},
		{"*/i-123", "ec2_instance/i-1234", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"", "", true},
		{"", "x", false},
		{"**", "abc", true},
		{"a*", "a", true},
	}
	for _, tt := range tests {
		if got := globMatch(tt.pattern, tt.name); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestParseRejectsBadPolicies(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"unknown field", `{"version":1,"supressions":[]}`, "unknown field"},
		{"wrong version", `{"version":2}`, "version must be 1"},
		{"missing version", `{}`, "version must be 1"},
		{"trailing data", `{"version":1} {"version":1}`, "unexpected data"},
		{"not json", `version: 1`, "decode"},
		{"typo in disabled rule", `{"version":1,"disabled_rules":["open_security_groups"]}`, "unknown rule"},
		{"wildcard disabled rule", `{"version":1,"disabled_rules":["open_*"]}`, "wildcards are not allowed"},
		{"bad override severity", `{"version":1,"severity_overrides":{"default_vpc_in_use":"urgent"}}`, "unknown severity"},
		{"override unknown rule", `{"version":1,"severity_overrides":{"nope":"low"}}`, "unknown rule"},
		{"suppression without reason", `{"version":1,"suppressions":[{"rule_id":"public_s3_bucket","resource":"*"}]}`, "reason is required"},
		{"suppression without resource", `{"version":1,"suppressions":[{"rule_id":"public_s3_bucket","reason":"x"}]}`, "resource is required"},
		{"suppression unknown rule", `{"version":1,"suppressions":[{"rule_id":"nope","resource":"*","reason":"x"}]}`, "unknown rule"},
		{"bad expiry", `{"version":1,"suppressions":[{"rule_id":"*","resource":"*","reason":"x","expires":"31/12/2026"}]}`, "YYYY-MM-DD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	p := Policy{Version: 1, Suppressions: []Suppression{
		{RuleID: "", Resource: "", Reason: "", Expires: "soon"},
	}}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"rule_id", "resource is required", "reason is required", "YYYY-MM-DD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q:\n%v", want, err)
		}
	}
}

func TestApplyDisabledRulesAndOverrides(t *testing.T) {
	p := mustParse(t, `{
		"version": 1,
		"disabled_rules": ["unused_security_group"],
		"severity_overrides": {"default_vpc_in_use": "info", "open_security_group": "critical"}
	}`)
	in := []findings.Finding{
		finding("unused_security_group", "security_group/sg-1", findings.SeverityInfo),
		finding("default_vpc_in_use", "vpc/vpc-1", findings.SeverityLow),
		finding("open_security_group", "security_group/sg-2", findings.SeverityMedium),
		finding("public_s3_bucket", "s3_bucket/b", findings.SeverityHigh),
	}
	snapshot := append([]findings.Finding(nil), in...)

	res := p.Apply(in, now)

	if !reflect.DeepEqual(in, snapshot) {
		t.Fatal("Apply must not mutate its input")
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "unused_security_group" ||
		res.Suppressed[0].Reason != "rule disabled by policy" {
		t.Fatalf("suppressed = %+v", res.Suppressed)
	}
	got := map[string]findings.Severity{}
	for _, f := range res.Kept {
		got[f.RuleID] = f.Severity
	}
	want := map[string]findings.Severity{
		"default_vpc_in_use":  findings.SeverityInfo,
		"open_security_group": findings.SeverityCritical,
		"public_s3_bucket":    findings.SeverityHigh,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kept severities = %v, want %v", got, want)
	}
}

func TestApplySuppressionsAndExpiry(t *testing.T) {
	p := mustParse(t, `{
		"version": 1,
		"suppressions": [
			{"rule_id": "public_s3_bucket", "resource": "s3_bucket/site-*", "reason": "static website", "expires": "2026-09-21"},
			{"rule_id": "open_security_group", "resource": "security_group/sg-old", "reason": "migration", "expires": "2026-09-20"},
			{"rule_id": "public_s3_bucket", "resource": "s3_bucket/fixed-long-ago", "reason": "was public once"},
			{"rule_id": "*", "resource": "ec2_instance/legacy", "reason": "decommissioning"}
		]
	}`)
	in := []findings.Finding{
		finding("public_s3_bucket", "s3_bucket/site-assets", findings.SeverityHigh),
		finding("public_s3_bucket", "s3_bucket/private-data", findings.SeverityHigh),
		finding("open_security_group", "security_group/sg-old", findings.SeverityHigh),
		finding("imdsv1_enabled", "ec2_instance/legacy", findings.SeverityMedium),
	}

	res := p.Apply(in, now)

	// The waiver expiring today still applies for the whole day; the one that
	// expired yesterday does not, so its finding returns to Kept.
	var suppressed []string
	for _, s := range res.Suppressed {
		suppressed = append(suppressed, s.ResourceID+"="+s.Reason)
	}
	wantSuppressed := []string{
		"s3_bucket/site-assets=static website",
		"ec2_instance/legacy=decommissioning",
	}
	if !reflect.DeepEqual(suppressed, wantSuppressed) {
		t.Fatalf("suppressed = %v, want %v", suppressed, wantSuppressed)
	}
	var kept []string
	for _, f := range res.Kept {
		kept = append(kept, f.ResourceID)
	}
	if !reflect.DeepEqual(kept, []string{"s3_bucket/private-data", "security_group/sg-old"}) {
		t.Fatalf("kept = %v", kept)
	}
	if len(res.Expired) != 1 || res.Expired[0].Resource != "security_group/sg-old" {
		t.Fatalf("expired = %+v", res.Expired)
	}
	if len(res.Unmatched) != 1 || res.Unmatched[0].Resource != "s3_bucket/fixed-long-ago" {
		t.Fatalf("unmatched (stale) waivers = %+v", res.Unmatched)
	}
}

func TestExpiredBoundary(t *testing.T) {
	s := Suppression{Expires: "2026-09-21"}
	tests := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 9, 20, 23, 59, 59, 0, time.UTC), false},
		{time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), false},
		{time.Date(2026, 9, 21, 23, 59, 59, 0, time.UTC), false},
		{time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC), true},
		// A local time on the 22nd that is still the 21st in UTC.
		{time.Date(2026, 9, 22, 1, 0, 0, 0, time.FixedZone("UTC+2", 2*3600)), false},
	}
	for _, tt := range tests {
		if got := s.Expired(tt.at); got != tt.want {
			t.Errorf("Expired(%s) = %v, want %v", tt.at.Format(time.RFC3339), got, tt.want)
		}
	}
	if (Suppression{}).Expired(now) {
		t.Error("a waiver with no expiry never expires")
	}
}

func TestApplyEmptyPolicyKeepsEverything(t *testing.T) {
	in := []findings.Finding{finding("public_s3_bucket", "s3_bucket/b", findings.SeverityHigh)}
	res := Policy{Version: 1}.Apply(in, now)
	if !reflect.DeepEqual(res.Kept, in) || len(res.Suppressed) != 0 {
		t.Fatalf("empty policy changed findings: %+v", res)
	}
	empty := Policy{Version: 1}.Apply(nil, now)
	if empty.Kept == nil {
		t.Fatal("Kept must be a non-nil empty slice so JSON output is [] rather than null")
	}
	if data, _ := json.Marshal(empty.Kept); string(data) != "[]" {
		t.Fatalf("Kept marshals as %s", data)
	}
}

func TestFirstMatchingSuppressionWins(t *testing.T) {
	p := mustParse(t, `{"version":1,"suppressions":[
		{"rule_id":"public_s3_bucket","resource":"*","reason":"broad"},
		{"rule_id":"public_s3_bucket","resource":"s3_bucket/b","reason":"specific"}
	]}`)
	res := p.Apply([]findings.Finding{finding("public_s3_bucket", "s3_bucket/b", findings.SeverityHigh)}, now)
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != "broad" {
		t.Fatalf("suppressed = %+v", res.Suppressed)
	}
	if len(res.Unmatched) != 1 || res.Unmatched[0].Reason != "specific" {
		t.Fatalf("the shadowed waiver should be reported as unmatched: %+v", res.Unmatched)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(good, []byte(`{"version":1,"disabled_rules":["default_vpc_in_use"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(good)
	if err != nil || len(p.DisabledRules) != 1 {
		t.Fatalf("Load = %+v, %v", p, err)
	}

	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "read policy") {
		t.Fatalf("missing file error = %v", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatalf("invalid file error should name the file: %v", err)
	}
}

// TestExamplePolicyIsValid keeps the policy shipped in examples/ loadable, so
// the documentation can never drift from what the parser accepts.
func TestExamplePolicyIsValid(t *testing.T) {
	p, err := Load(filepath.Join("..", "..", "examples", "infralens.policy.json"))
	if err != nil {
		t.Fatalf("example policy must load: %v", err)
	}
	if len(p.DisabledRules) == 0 || len(p.SeverityOverrides) == 0 || len(p.Suppressions) == 0 {
		t.Fatalf("example should demonstrate every feature: %+v", p)
	}
	for _, s := range p.Suppressions {
		if s.Owner == "" || s.Expires == "" {
			t.Errorf("example waivers should model good practice (owner and expiry): %+v", s)
		}
	}
}
