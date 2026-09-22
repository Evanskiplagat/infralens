// Package report renders findings for the places people actually read them:
// SARIF for code-scanning platforms and security tooling, and Markdown for
// pull-request comments and CI job summaries. It depends only on findings, so
// any output can be produced from a stored scan without AWS access.
package report

import (
	"time"

	"infralens/internal/findings"
)

// Meta describes the scan a report was generated from.
type Meta struct {
	ScanID    string
	AccountID string
	Regions   []string
	// Status is the scan status ("complete", "partial", ...). Reports for a
	// partial scan carry a warning that findings may be incomplete.
	Status string
	// ToolVersion is the InfraLens version, included in machine-readable
	// output so results can be traced to the build that produced them.
	ToolVersion string
	// GeneratedAt is when the report was produced.
	GeneratedAt time.Time
}

// Input bundles everything a report needs.
type Input struct {
	Meta       Meta
	Findings   []findings.Finding
	Suppressed []findings.Suppressed
	// Rules describes the rules that can appear in Findings. Rules missing
	// from it are still reported, just without remediation guidance.
	Rules []findings.RuleInfo
}

// ruleIndex maps rule IDs to their descriptions.
func (in Input) ruleIndex() map[string]findings.RuleInfo {
	idx := make(map[string]findings.RuleInfo, len(in.Rules))
	for _, r := range in.Rules {
		idx[r.ID] = r
	}
	return idx
}

// counts tallies findings per severity.
func counts(fs []findings.Finding) map[findings.Severity]int {
	c := make(map[findings.Severity]int, len(findings.AllSeverities()))
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}
