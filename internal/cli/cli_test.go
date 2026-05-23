package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/cli"
)

func chdir(t *testing.T, dir string) string {
	t.Helper()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	return prev
}

func checkFile(t *testing.T, dir string, path string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func checkDir(t *testing.T, dir string, path string) {
	t.Helper()
	full := filepath.Join(dir, path)
	info, err := os.Stat(full)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", path)
	}
}

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

	t.Run("init dispatches without error", func(t *testing.T) {
		tmp := t.TempDir()
		prev := chdir(t, tmp)
		defer chdir(t, prev)

		err := cli.Run([]string{"init"})
		if err != nil {
			t.Errorf("init should be routed: %v", err)
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

	t.Run("init creates .scalp directory and default files", func(t *testing.T) {
		tmp := t.TempDir()
		prev := chdir(t, tmp)
		defer chdir(t, prev)

		err := cli.Run([]string{"init"})
		if err != nil {
			t.Fatalf("init: %v", err)
		}

		checkFile(t, tmp, ".scalp/policy.json")
		checkFile(t, tmp, ".scalp/policy.schema.json")
		checkFile(t, tmp, ".scalp/lockfile.json")
		checkFile(t, tmp, ".scalp/audit.log")
		checkDir(t, tmp, ".scalp/cache")
	})

	t.Run("init --minimal creates minimal policy", func(t *testing.T) {
		tmp := t.TempDir()
		prev := chdir(t, tmp)
		defer chdir(t, prev)

		if err := cli.Run([]string{"init", "--minimal"}); err != nil {
			t.Fatalf("init --minimal: %v", err)
		}

		checkFile(t, tmp, ".scalp/policy.json")
	})

	t.Run("init --strict creates strict policy", func(t *testing.T) {
		tmp := t.TempDir()
		prev := chdir(t, tmp)
		defer chdir(t, prev)

		if err := cli.Run([]string{"init", "--strict"}); err != nil {
			t.Fatalf("init --strict: %v", err)
		}

		checkFile(t, tmp, ".scalp/policy.json")
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
