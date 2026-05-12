package ctxutil

import (
	"context"
	"fmt"
)

// Check returns a wrapped context error when canceled or deadline exceeded.
func Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}
	return nil
}
