// Command infralens is the InfraLens CLI entrypoint.
package main

import (
	"context"
	"fmt"
	"os"

	"infralens/internal/cli"
)

func main() {
	if err := cli.Execute(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "infralens:", err)
		os.Exit(1)
	}
}
