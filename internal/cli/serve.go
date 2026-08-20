package cli

import (
	"context"
	"errors"
)

// runServe is a placeholder for the optional future local web viewer.
// It is registered now so the command surface is stable, but does not
// build a UI ahead of the CLI it would sit on top of. See docs/roadmap.md.
func runServe(ctx context.Context, args []string) error {
	return errors.New("infralens serve is not implemented yet; see docs/roadmap.md for the plan")
}
