// Package policy lets a team tune InfraLens's findings without forking its
// rules: disable rules that do not apply, re-rank severities to match its
// risk appetite, and waive individual findings with a written reason and
// an expiry date so exceptions cannot quietly become permanent.
//
// A policy is a small JSON document:
//
//	{
//	  "version": 1,
//	  "disabled_rules": ["unused_security_group"],
//	  "severity_overrides": {"default_vpc_in_use": "info"},
//	  "suppressions": [
//	    {
//	      "rule_id": "public_s3_bucket",
//	      "resource": "s3_bucket/marketing-site-*",
//	      "reason": "Public static website, reviewed by security",
//	      "owner": "platform-team",
//	      "expires": "2027-03-31"
//	    }
//	  ]
//	}
//
// Policies are applied after a scan, when findings are reported, so the same
// stored scan can be evaluated under different policies.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"infralens/internal/findings"
)

// CurrentVersion is the only policy schema version this build understands.
const CurrentVersion = 1

// dateLayout is the format of Suppression.Expires.
const dateLayout = "2006-01-02"

// Policy is a parsed, validated set of findings adjustments.
type Policy struct {
	Version           int                          `json:"version"`
	DisabledRules     []string                     `json:"disabled_rules,omitempty"`
	SeverityOverrides map[string]findings.Severity `json:"severity_overrides,omitempty"`
	Suppressions      []Suppression                `json:"suppressions,omitempty"`
}

// Suppression waives findings for one rule on the resources matching a
// pattern. Both RuleID and Resource accept "*" wildcards.
type Suppression struct {
	RuleID   string `json:"rule_id"`
	Resource string `json:"resource"`
	Reason   string `json:"reason"`
	Owner    string `json:"owner,omitempty"`
	// Expires is the last day (UTC, inclusive) the waiver applies, as
	// YYYY-MM-DD. An empty value means the waiver never expires.
	Expires string `json:"expires,omitempty"`
}

// Load reads and validates the policy file at path.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	p, err := Parse(bytes.NewReader(data))
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Parse decodes and validates a policy. Unknown fields are rejected so a
// typo such as "supressions" fails loudly instead of silently disabling a
// waiver (or, worse, silently not applying one).
func Parse(r io.Reader) (Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return Policy{}, errors.New("decode: unexpected data after the policy object")
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate reports every problem in the policy at once, so an author can fix
// them in one pass.
func (p Policy) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if p.Version != CurrentVersion {
		add("version must be %d, got %d", CurrentVersion, p.Version)
	}
	for _, id := range p.DisabledRules {
		if problem := checkRuleID(id, false); problem != "" {
			add("disabled_rules: %s", problem)
		}
	}
	for id, sev := range p.SeverityOverrides {
		if problem := checkRuleID(id, false); problem != "" {
			add("severity_overrides: %s", problem)
		}
		if !sev.Valid() {
			add("severity_overrides[%q]: unknown severity %q", id, sev)
		}
	}
	for i, s := range p.Suppressions {
		where := fmt.Sprintf("suppressions[%d]", i)
		if problem := checkRuleID(s.RuleID, true); problem != "" {
			add("%s: rule_id: %s", where, problem)
		}
		if strings.TrimSpace(s.Resource) == "" {
			add("%s: resource is required (use \"*\" to match every resource)", where)
		}
		if strings.TrimSpace(s.Reason) == "" {
			add("%s: reason is required so the waiver can be audited", where)
		}
		if s.Expires != "" {
			if _, err := time.Parse(dateLayout, s.Expires); err != nil {
				add("%s: expires %q is not a YYYY-MM-DD date", where, s.Expires)
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid policy:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// checkRuleID returns a description of what is wrong with a rule ID, or ""
// when it is acceptable. Typos in rule IDs would otherwise turn a policy
// into a silent no-op, so exact IDs must name a built-in rule; wildcards are
// only accepted where allowed.
func checkRuleID(id string, allowWildcard bool) string {
	switch {
	case strings.TrimSpace(id) == "":
		return "an empty rule ID is not allowed"
	case strings.Contains(id, "*"):
		if allowWildcard {
			return ""
		}
		return fmt.Sprintf("%q: wildcards are not allowed here", id)
	}
	if _, ok := findings.LookupRule(id); !ok {
		return fmt.Sprintf("unknown rule %q (run `infralens rules` to list rule IDs)", id)
	}
	return ""
}

// expiry returns the instant after which the suppression stops applying, and
// false when it never expires.
func (s Suppression) expiry() (time.Time, bool) {
	if s.Expires == "" {
		return time.Time{}, false
	}
	day, err := time.Parse(dateLayout, s.Expires)
	if err != nil {
		return time.Time{}, false
	}
	return day.Add(24 * time.Hour), true // inclusive of the whole expiry day
}

// Expired reports whether the waiver no longer applies at now.
func (s Suppression) Expired(now time.Time) bool {
	end, ok := s.expiry()
	return ok && !now.UTC().Before(end)
}

func (s Suppression) matches(f findings.Finding) bool {
	return globMatch(s.RuleID, f.RuleID) && globMatch(s.Resource, f.ResourceID)
}

// Result is the outcome of applying a policy to a set of findings.
type Result struct {
	// Kept are the findings that still need attention, with any severity
	// overrides applied.
	Kept []findings.Finding
	// Suppressed are findings removed by a disabled rule or a waiver.
	Suppressed []findings.Suppressed
	// Expired are waivers past their expiry date. They no longer suppress
	// anything, so the findings they covered are back in Kept.
	Expired []Suppression
	// Unmatched are unexpired waivers that matched no finding. They are
	// usually stale (the issue was fixed) and should be removed.
	Unmatched []Suppression
}

// Apply evaluates the policy against fs at time now. It never mutates fs.
//
// Order matters: disabled rules are dropped first, severity overrides are
// applied next, and waivers last. Kept is never nil, so it marshals as an
// empty JSON array.
func (p Policy) Apply(fs []findings.Finding, now time.Time) Result {
	res := Result{Kept: make([]findings.Finding, 0, len(fs))}

	disabled := make(map[string]bool, len(p.DisabledRules))
	for _, id := range p.DisabledRules {
		disabled[id] = true
	}

	active := make([]int, 0, len(p.Suppressions))
	for i, s := range p.Suppressions {
		if s.Expired(now) {
			res.Expired = append(res.Expired, s)
			continue
		}
		active = append(active, i)
	}
	used := make(map[int]bool, len(active))

	for _, f := range fs {
		if disabled[f.RuleID] {
			res.Suppressed = append(res.Suppressed, findings.Suppressed{
				Finding: f, Reason: "rule disabled by policy",
			})
			continue
		}
		if override, ok := p.SeverityOverrides[f.RuleID]; ok {
			f.Severity = override
		}
		waived := false
		for _, i := range active {
			if p.Suppressions[i].matches(f) {
				used[i] = true
				res.Suppressed = append(res.Suppressed, findings.Suppressed{
					Finding: f, Reason: p.Suppressions[i].Reason,
				})
				waived = true
				break
			}
		}
		if !waived {
			res.Kept = append(res.Kept, f)
		}
	}

	for _, i := range active {
		if !used[i] {
			res.Unmatched = append(res.Unmatched, p.Suppressions[i])
		}
	}
	return res
}

// globMatch reports whether name matches pattern, where "*" matches any run
// of characters (including "/", unlike path.Match, because resource IDs such
// as "s3_bucket/site-assets" contain slashes).
func globMatch(pattern, name string) bool {
	px, nx := 0, 0
	nextPx, nextNx := 0, 0
	for px < len(pattern) || nx < len(name) {
		if px < len(pattern) {
			switch c := pattern[px]; {
			case c == '*':
				nextPx, nextNx = px, nx+1
				px++
				continue
			case nx < len(name) && c == name[nx]:
				px++
				nx++
				continue
			}
		}
		if 0 < nextNx && nextNx <= len(name) {
			px, nx = nextPx, nextNx
			continue
		}
		return false
	}
	return true
}
