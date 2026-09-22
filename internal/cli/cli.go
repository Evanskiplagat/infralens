// Package cli implements InfraLens's command-line interface: parsing
// subcommands and flags with the standard library and wiring them to
// the domain packages (awsdiscovery, normalize, graph, findings,
// storage, export, diff).
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Version is the InfraLens release. It is stamped into reports so results
// can be traced to a build; release builds override it with
// -ldflags "-X infralens/internal/cli.Version=v1.2.3".
var Version = "dev"

type command struct {
	name  string
	short string
	run   func(ctx context.Context, args []string) error
}

func commands() []command {
	return []command{
		{"scan", "Discover AWS resources and persist a new scan", runScan},
		{"graph", "Build and display the resource graph for a scan", runGraph},
		{"findings", "Report exposure findings as a table, JSON, SARIF, or Markdown", runFindings},
		{"diff", "Compare two scans", runDiff},
		{"export", "Export a scan as JSON, CSV, or DOT", runExport},
		{"scans", "List stored scans", runScans},
		{"rules", "List the built-in findings rules and how to fix them", runRules},
		{"version", "Print the InfraLens version", runVersion},
		{"serve", "(planned) Serve a local read-only viewer", runServe},
	}
}

// Execute dispatches args[0] to the matching subcommand.
func Execute(ctx context.Context, args []string) error {
	cmds := commands()

	if len(args) == 0 {
		printUsage(cmds)
		return errors.New("no command given")
	}

	name := args[0]
	for _, c := range cmds {
		if c.name == name {
			return c.run(ctx, args[1:])
		}
	}

	printUsage(cmds)
	return fmt.Errorf("unknown command %q", name)
}

func printUsage(cmds []command) {
	fmt.Fprintln(os.Stderr, "InfraLens: AWS infrastructure discovery, graphing, and findings")
	fmt.Fprintln(os.Stderr, "\nUsage:\n  infralens <command> [flags]")
	fmt.Fprintln(os.Stderr, "\nCommands:")
	for _, c := range cmds {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", c.name, c.short)
	}
}
