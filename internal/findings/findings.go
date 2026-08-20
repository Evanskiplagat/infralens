// Package findings evaluates rules against a scan's graph to surface
// likely public exposure and risky topology.
package findings

import "infralens/internal/graph"

// Severity ranks how urgent a Finding is.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// Finding is a single rule violation attached to a resource.
type Finding struct {
	RuleID      string
	ResourceID  string
	Severity    Severity
	Title       string
	Description string
}

// Rule inspects a graph and reports any findings it detects.
type Rule interface {
	ID() string
	Evaluate(g *graph.Graph) []Finding
}

// Run evaluates every rule against g and returns the combined findings.
func Run(g *graph.Graph, rules []Rule) []Finding {
	var out []Finding
	for _, r := range rules {
		out = append(out, r.Evaluate(g)...)
	}
	return out
}
