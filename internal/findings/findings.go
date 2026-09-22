// Package findings evaluates rules against a scan's graph to surface
// likely public exposure and risky topology.
package findings

import (
	"sort"

	"infralens/internal/graph"
)

// Severity ranks how urgent a Finding is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities lists every severity from least to most urgent.
func AllSeverities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// Rank orders severities so they can be compared and thresholded: a
// higher rank is more urgent. An unrecognized severity ranks below info.
func (s Severity) Rank() int {
	for i, known := range AllSeverities() {
		if s == known {
			return i
		}
	}
	return -1
}

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// Finding is a single rule violation attached to a resource.
type Finding struct {
	RuleID      string
	ResourceID  string
	Severity    Severity
	Title       string
	Description string
}

// Suppressed is a finding that a policy removed from the actionable set,
// together with the justification that removed it.
type Suppressed struct {
	Finding
	Reason string
}

// RuleInfo is the static, human-facing description of a rule. It lives
// with the rule (not with each Finding) so stored scans stay small and
// remediation guidance can improve without rewriting scan history.
type RuleInfo struct {
	ID string
	// Title is a short, resource-independent name for the rule.
	Title string
	// Description explains what the rule detects and why it matters.
	Description string
	// Remediation tells the reader how to fix a violation.
	Remediation string
	// DefaultSeverity is the severity most findings carry; a rule may
	// raise or lower it per finding based on context.
	DefaultSeverity Severity
	// References point at upstream guidance, such as AWS documentation.
	References []string
	// Tags group rules for filtering and for SARIF consumers.
	Tags []string
}

// Rule inspects a graph and reports any findings it detects.
type Rule interface {
	ID() string
	Info() RuleInfo
	Evaluate(g *graph.Graph) []Finding
}

// Run evaluates every rule against g and returns the combined findings,
// ordered most severe first and then by rule and resource so output is
// stable across runs (the graph itself is an unordered map).
func Run(g *graph.Graph, rules []Rule) []Finding {
	var out []Finding
	for _, r := range rules {
		out = append(out, r.Evaluate(g)...)
	}
	Sort(out)
	return out
}

// Sort orders findings most severe first, then by rule ID, resource ID and
// title. It sorts in place.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
			return ra > rb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		return a.Title < b.Title
	})
}

// Catalog returns the descriptions of the given rules, ordered by ID.
func Catalog(rules []Rule) []RuleInfo {
	infos := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		infos = append(infos, r.Info())
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos
}

// LookupRule finds a rule's description by ID among the built-in rules.
func LookupRule(id string) (RuleInfo, bool) {
	for _, r := range DefaultRules() {
		if r.ID() == id {
			return r.Info(), true
		}
	}
	return RuleInfo{}, false
}
