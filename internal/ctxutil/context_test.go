package ctxutil_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"scal-p/internal/ctxutil"
)

func TestCheck(t *testing.T) {
	t.Run("background returns nil", func(t *testing.T) {
		if err := ctxutil.Check(context.Background()); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("canceled returns error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := ctxutil.Check(ctx); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("deadline exceeded returns error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
		defer cancel()
		<-ctx.Done()
		if err := ctxutil.Check(ctx); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("error wraps context cause", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := ctxutil.Check(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}
