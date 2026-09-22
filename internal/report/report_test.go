package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"infralens/internal/findings"
)

func sampleInput() Input {
	return Input{
		Meta: Meta{
			ScanID: "20260921T101500Z", AccountID: "111122223333", Regions: []string{"eu-west-1", "us-east-1"},
			Status: "complete", ToolVersion: "1.2.3", GeneratedAt: time.Date(2026, 9, 21, 10, 15, 0, 0, time.UTC),
		},
		Findings: []findings.Finding{
			{RuleID: findings.RuleOpenSecurityGroup, ResourceID: "security_group/sg-1", Severity: findings.SeverityCritical,
				Title: "Security group web allows unrestricted ingress", Description: "web permits inbound all traffic from 0.0.0.0/0."},
			{RuleID: findings.RuleS3PublicAccessBlock, ResourceID: "s3_bucket/logs", Severity: findings.SeverityMedium,
				Title: "S3 bucket logs does not block public access", Description: "Bucket logs has settings disabled."},
			{RuleID: findings.RuleDefaultVPCInUse, ResourceID: "vpc/vpc-1", Severity: findings.SeverityLow,
				Title: "Default VPC", Description: "pipes | in text\nand newlines"},
		},
		Suppressed: []findings.Suppressed{
			{Finding: findings.Finding{RuleID: findings.RulePublicS3Bucket, ResourceID: "s3_bucket/site", Severity: findings.SeverityHigh,
				Title: "S3 bucket site is publicly accessible"}, Reason: "static website"},
		},
		Rules: findings.Catalog(findings.DefaultRules()),
	}
}

func decodeSARIF(t *testing.T, in Input) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, in); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	return doc
}

func TestSARIFStructure(t *testing.T) {
	doc := decodeSARIF(t, sampleInput())

	if doc["version"] != "2.1.0" || doc["$schema"] != sarifSchema {
		t.Fatalf("version/schema = %v / %v", doc["version"], doc["$schema"])
	}
	runs := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("want one run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)

	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "InfraLens" || driver["version"] != "1.2.3" {
		t.Errorf("driver = %v", driver)
	}
	rules := driver["rules"].([]any)
	ruleIDs := make([]string, len(rules))
	for i, r := range rules {
		ruleIDs[i] = r.(map[string]any)["id"].(string)
	}
	wantIDs := []string{"default_vpc_in_use", "open_security_group", "public_s3_bucket", "s3_public_access_block_disabled"}
	if fmt.Sprint(ruleIDs) != fmt.Sprint(wantIDs) {
		t.Fatalf("only rules that fired (or were suppressed) should be listed, sorted: got %v want %v", ruleIDs, wantIDs)
	}

	results := run["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("want 3 findings + 1 suppressed = 4 results, got %d", len(results))
	}
	for _, r := range results {
		res := r.(map[string]any)
		idx := int(res["ruleIndex"].(float64))
		if ruleIDs[idx] != res["ruleId"] {
			t.Errorf("ruleIndex %d points at %s, but result is for %s", idx, ruleIDs[idx], res["ruleId"])
		}
		loc := res["locations"].([]any)[0].(map[string]any)
		uri := loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
		if !strings.HasPrefix(uri, "aws/111122223333/") {
			t.Errorf("artifact uri = %q", uri)
		}
		if fp := res["partialFingerprints"].(map[string]any)["infralens/v1"].(string); len(fp) != 32 {
			t.Errorf("fingerprint %q should be 32 hex chars", fp)
		}
	}
}

func TestSARIFLevelsAndSuppressions(t *testing.T) {
	doc := decodeSARIF(t, sampleInput())
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)

	levels := map[string]string{}
	var suppressed map[string]any
	for _, r := range results {
		res := r.(map[string]any)
		levels[res["ruleId"].(string)] = res["level"].(string)
		if _, ok := res["suppressions"]; ok {
			suppressed = res
		}
	}
	want := map[string]string{
		"open_security_group":             "error",
		"s3_public_access_block_disabled": "warning",
		"default_vpc_in_use":              "note",
		"public_s3_bucket":                "error",
	}
	for id, level := range want {
		if levels[id] != level {
			t.Errorf("%s level = %q, want %q", id, levels[id], level)
		}
	}
	if suppressed == nil || suppressed["ruleId"] != "public_s3_bucket" {
		t.Fatalf("suppressed result missing: %v", suppressed)
	}
	sup := suppressed["suppressions"].([]any)[0].(map[string]any)
	if sup["kind"] != "external" || sup["justification"] != "static website" {
		t.Errorf("suppression = %v", sup)
	}
}

func TestSARIFEmptyAndUnknownRule(t *testing.T) {
	empty := decodeSARIF(t, Input{Meta: Meta{ScanID: "s", Status: "complete"}})
	run := empty["runs"].([]any)[0].(map[string]any)
	if res, ok := run["results"].([]any); !ok || len(res) != 0 {
		t.Fatalf("results must be an empty array, got %v", run["results"])
	}
	if rules, ok := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("rules must be an empty array, got %v", rules)
	}

	// A finding for a rule missing from the catalog is still reported.
	doc := decodeSARIF(t, Input{
		Meta:     Meta{ScanID: "s"},
		Findings: []findings.Finding{{RuleID: "custom_rule", ResourceID: "x/1", Severity: findings.SeverityLow, Title: "T"}},
	})
	res := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(res) != 1 || res[0].(map[string]any)["ruleId"] != "custom_rule" {
		t.Fatalf("results = %v", res)
	}
}

func TestSARIFFingerprintIgnoresWording(t *testing.T) {
	a := findings.Finding{RuleID: "r", ResourceID: "x/1", Severity: findings.SeverityHigh, Title: "old"}
	b := findings.Finding{RuleID: "r", ResourceID: "x/1", Severity: findings.SeverityLow, Title: "new", Description: "changed"}
	c := findings.Finding{RuleID: "r", ResourceID: "x/2"}
	if fingerprint(a) != fingerprint(b) {
		t.Error("fingerprint must not depend on title, description or severity")
	}
	if fingerprint(a) == fingerprint(c) {
		t.Error("different resources must have different fingerprints")
	}
}

func TestSARIFMarksFailedScans(t *testing.T) {
	doc := decodeSARIF(t, Input{Meta: Meta{ScanID: "s", Status: "failed"}})
	inv := doc["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false {
		t.Errorf("failed scan should not be reported as successful: %v", inv)
	}
}

func TestMarkdownSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleInput()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"## InfraLens findings",
		"`20260921T101500Z`",
		"account `111122223333`",
		"| CRITICAL | 1 |",
		"| MEDIUM | 1 |",
		"| LOW | 1 |",
		"| **Total** | **3** |",
		"<details><summary>How to fix</summary>",
		"1 finding(s) suppressed by policy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "| HIGH |") || strings.Contains(out, "| INFO |") {
		t.Error("severities with no findings should be omitted from the summary")
	}
	if strings.Index(out, "| CRITICAL | `open_security_group`") > strings.Index(out, "| LOW | `default_vpc_in_use`") {
		t.Error("findings should be ordered most severe first")
	}
	if strings.Contains(out, "pipes | in text") || !strings.Contains(out, `pipes \| in text and newlines`) {
		t.Errorf("table cells must escape pipes and newlines:\n%s", out)
	}
}

func TestMarkdownNoFindingsAndPartialWarning(t *testing.T) {
	var buf bytes.Buffer
	in := Input{Meta: Meta{ScanID: "s1", Status: "partial"}, Suppressed: sampleInput().Suppressed}
	if err := WriteMarkdown(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"No actionable findings.", "this scan is partial", "1 finding(s) suppressed"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownTruncatesLargeReports(t *testing.T) {
	in := Input{Meta: Meta{ScanID: "big"}}
	for i := 0; i < maxMarkdownRows+25; i++ {
		in.Findings = append(in.Findings, findings.Finding{
			RuleID: "custom", ResourceID: fmt.Sprintf("x/%03d", i), Severity: findings.SeverityLow,
		})
	}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := strings.Count(out, "| `custom` |"); got != maxMarkdownRows {
		t.Errorf("rows = %d, want %d", got, maxMarkdownRows)
	}
	if !strings.Contains(out, fmt.Sprintf("Showing the %d most severe of %d findings", maxMarkdownRows, maxMarkdownRows+25)) {
		t.Errorf("truncation notice missing:\n%s", out[len(out)-300:])
	}
	if len(out) > 65000 {
		t.Errorf("report is %d bytes, too large for a GitHub comment", len(out))
	}
}
