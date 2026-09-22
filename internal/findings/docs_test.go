package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRulesDocListsEveryRule keeps docs/rules.md honest: adding a rule
// without documenting it (or leaving a removed rule in the docs) fails here.
func TestRulesDocListsEveryRule(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "rules.md"))
	if err != nil {
		t.Fatalf("docs/rules.md must exist: %v", err)
	}
	doc := string(data)
	for _, info := range Catalog(DefaultRules()) {
		if !strings.Contains(doc, "## `"+info.ID+"`") {
			t.Errorf("docs/rules.md has no section for rule %q", info.ID)
		}
		if !strings.Contains(doc, info.Remediation) {
			t.Errorf("docs/rules.md is stale: remediation for %q differs from the rule's", info.ID)
		}
	}
	if got, want := strings.Count(doc, "\n## `"), len(DefaultRules()); got != want {
		t.Errorf("docs/rules.md documents %d rules, but there are %d built in", got, want)
	}
}
