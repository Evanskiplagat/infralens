package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"infralens/internal/export"
	"infralens/internal/findings"
)

// runRules lists the built-in rules. It needs no AWS credentials, config or
// database, so it is safe to run anywhere, including when writing a policy
// file that has to name rule IDs.
func runRules(_ context.Context, args []string) error {
	return writeRules(os.Stdout, args)
}

func writeRules(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	id := fs.String("id", "", "Show full details for a single rule ID")
	format := fs.String("format", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown format %q (want table or json)", *format)
	}

	catalog := findings.Catalog(findings.DefaultRules())
	if *id != "" {
		info, ok := findings.LookupRule(*id)
		if !ok {
			return fmt.Errorf("unknown rule %q (run `infralens rules` to list rule IDs)", *id)
		}
		catalog = []findings.RuleInfo{info}
	}

	if *format == "json" {
		return export.WriteJSON(w, catalog)
	}
	if *id != "" {
		printRuleDetail(w, catalog[0])
		return nil
	}
	fmt.Fprintf(w, "%-34s %-9s %s\n", "RULE", "SEVERITY", "TITLE")
	for _, info := range catalog {
		fmt.Fprintf(w, "%-34s %-9s %s\n", info.ID, info.DefaultSeverity, info.Title)
	}
	return nil
}

func printRuleDetail(w io.Writer, info findings.RuleInfo) {
	fmt.Fprintf(w, "%s (%s)\n\n", info.Title, info.ID)
	fmt.Fprintf(w, "Default severity: %s\n", info.DefaultSeverity)
	if len(info.Tags) > 0 {
		fmt.Fprintf(w, "Tags: %s\n", strings.Join(info.Tags, ", "))
	}
	fmt.Fprintf(w, "\n%s\n\nRemediation: %s\n", info.Description, info.Remediation)
	for _, ref := range info.References {
		fmt.Fprintf(w, "Reference: %s\n", ref)
	}
}

func runVersion(_ context.Context, _ []string) error {
	fmt.Println("infralens", Version)
	return nil
}
