package report

import (
	"fmt"
	"io"
	"strings"

	"infralens/internal/findings"
)

// maxMarkdownRows caps the findings table so the output stays under GitHub's
// 65,536-character limit for comments and job summaries on large accounts.
const maxMarkdownRows = 100

var severityBadge = map[findings.Severity]string{
	findings.SeverityCritical: "CRITICAL",
	findings.SeverityHigh:     "HIGH",
	findings.SeverityMedium:   "MEDIUM",
	findings.SeverityLow:      "LOW",
	findings.SeverityInfo:     "INFO",
}

// WriteMarkdown writes a GitHub-flavored Markdown summary: a severity count
// table, the most urgent findings with remediation guidance, and a note on
// anything a policy suppressed.
func WriteMarkdown(w io.Writer, in Input) error {
	var b strings.Builder
	idx := in.ruleIndex()

	b.WriteString("## InfraLens findings\n\n")
	fmt.Fprintf(&b, "Scan `%s`", escapeCode(in.Meta.ScanID))
	if in.Meta.AccountID != "" {
		fmt.Fprintf(&b, " · account `%s`", escapeCode(in.Meta.AccountID))
	}
	if len(in.Meta.Regions) > 0 {
		fmt.Fprintf(&b, " · %s", escapeCode(strings.Join(in.Meta.Regions, ", ")))
	}
	b.WriteString("\n\n")

	if in.Meta.Status == "partial" {
		b.WriteString("> **Warning:** this scan is partial. Some regions or services failed, so " +
			"the findings below may be incomplete.\n\n")
	}

	if len(in.Findings) == 0 {
		b.WriteString("No actionable findings.\n")
		writeSuppressedNote(&b, in.Suppressed)
		_, err := io.WriteString(w, b.String())
		return err
	}

	tally := counts(in.Findings)
	b.WriteString("| Severity | Count |\n| --- | ---: |\n")
	sevs := findings.AllSeverities()
	for i := len(sevs) - 1; i >= 0; i-- {
		if n := tally[sevs[i]]; n > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", severityBadge[sevs[i]], n)
		}
	}
	fmt.Fprintf(&b, "| **Total** | **%d** |\n\n", len(in.Findings))

	// Findings arrive sorted by the caller; sort defensively so a report is
	// always most-severe-first regardless of the source.
	sorted := append([]findings.Finding(nil), in.Findings...)
	findings.Sort(sorted)

	b.WriteString("| Severity | Rule | Resource | Detail |\n| --- | --- | --- | --- |\n")
	shown := sorted
	if len(shown) > maxMarkdownRows {
		shown = shown[:maxMarkdownRows]
	}
	for _, f := range shown {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n",
			severityBadge[f.Severity], escapeCode(f.RuleID), escapeCode(f.ResourceID), escapeCell(f.Description))
	}
	if len(sorted) > len(shown) {
		fmt.Fprintf(&b, "\n_Showing the %d most severe of %d findings; use `infralens findings --format json` for the full list._\n",
			len(shown), len(sorted))
	}

	// One remediation block per rule that fired, rather than repeating the
	// same advice for every resource.
	seen := map[string]bool{}
	var guidance []findings.RuleInfo
	for _, f := range sorted {
		if info, ok := idx[f.RuleID]; ok && !seen[f.RuleID] {
			seen[f.RuleID] = true
			guidance = append(guidance, info)
		}
	}
	if len(guidance) > 0 {
		b.WriteString("\n<details><summary>How to fix</summary>\n\n")
		for _, info := range guidance {
			fmt.Fprintf(&b, "**%s** (`%s`)\n\n%s\n\n", escapeCell(info.Title), escapeCode(info.ID), info.Remediation)
			for _, ref := range info.References {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			if len(info.References) > 0 {
				b.WriteString("\n")
			}
		}
		b.WriteString("</details>\n")
	}

	writeSuppressedNote(&b, in.Suppressed)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeSuppressedNote(b *strings.Builder, suppressed []findings.Suppressed) {
	if len(suppressed) == 0 {
		return
	}
	fmt.Fprintf(b, "\n_%d finding(s) suppressed by policy._\n", len(suppressed))
}

// escapeCell makes text safe inside a Markdown table cell: pipes would end
// the cell and newlines would end the row.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// escapeCode makes text safe inside an inline code span within a table.
func escapeCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return escapeCell(s)
}
