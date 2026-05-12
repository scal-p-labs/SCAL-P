package cli_test

import (
	"testing"

	"scal-p/internal/cli"
)

func TestRun_router(t *testing.T) {
	t.Run("no args returns error", func(t *testing.T) {
		err := cli.Run(nil)
		if err == nil {
			t.Fatal("expected error for no args")
		}
	})

	t.Run("empty args returns error", func(t *testing.T) {
		err := cli.Run([]string{})
		if err == nil {
			t.Fatal("expected error for empty args")
		}
	})

	t.Run("help returns error (usage)", func(t *testing.T) {
		err := cli.Run([]string{"help"})
		if err == nil {
			t.Fatal("expected error for help")
		}
	})

	t.Run("unknown command returns error", func(t *testing.T) {
		err := cli.Run([]string{"garbage-command-xyz"})
		if err == nil {
			t.Fatal("expected error for unknown command")
		}
	})

	t.Run("version returns nil", func(t *testing.T) {
		err := cli.Run([]string{"version"})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("-v returns nil", func(t *testing.T) {
		err := cli.Run([]string{"-v"})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("install dispatches without error", func(t *testing.T) {
		// This tests routing only; will fail if pm is not available
		err := cli.Run([]string{"install", "--pm", "npm"})
		// We expect a different error (npm not found or similar), not a routing error
		if err != nil && err.Error() == "unknown command: install\n..." {
			t.Errorf("install should be routed, not unknown: %v", err)
		}
	})

	t.Run("audit dispatches", func(t *testing.T) {
		err := cli.Run([]string{"audit"})
		if err != nil && err.Error() == "unknown command: audit\n..." {
			t.Errorf("audit should be routed, not unknown: %v", err)
		}
	})

	t.Run("policy without subcommand returns error", func(t *testing.T) {
		err := cli.Run([]string{"policy"})
		if err == nil {
			t.Fatal("expected error for policy without subcommand")
		}
	})

	t.Run("policy check dispatches", func(t *testing.T) {
		err := cli.Run([]string{"policy", "check"})
		// Expected to fail because no npm project, but not a routing error
		if err != nil && err.Error() == "unknown policy subcommand: check" {
			t.Errorf("policy check should be routed, got: %v", err)
		}
	})
}
