package pnpm_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/pkgmanager"
	"scal-p/internal/pnpm"
)

// mockExec overrides pnpm's command factory to produce controlled output.
func mockExec(t *testing.T, stdout string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "stdout")
	scriptPath := filepath.Join(dir, "mock.sh")

	if err := os.WriteFile(outPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\ncat '%s'\nexit %d\n", outPath, exitCode)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	restore := pnpm.SetExecCommand(func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, scriptPath)
	})
	t.Cleanup(func() { pnpm.SetExecCommand(restore) })
}

// mockExecCheckArgs overrides pnpm's command factory and also checks the args.
func mockExecCheckArgs(t *testing.T, stdout string, exitCode int, checkFn func(name string, args []string)) {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "stdout")
	scriptPath := filepath.Join(dir, "mock.sh")

	if err := os.WriteFile(outPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\ncat '%s'\nexit %d\n", outPath, exitCode)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	restore := pnpm.SetExecCommand(func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		checkFn(name, arg)
		return exec.CommandContext(ctx, scriptPath)
	})
	t.Cleanup(func() { pnpm.SetExecCommand(restore) })
}

// ──────────────────────────────────────────────
// Adapter interface compliance
// ──────────────────────────────────────────────

func TestAdapterImplementsInterface(t *testing.T) {
	var _ pkgmanager.PackageManager = &pnpm.Adapter{}
}

func TestAdapterName(t *testing.T) {
	a := &pnpm.Adapter{}
	if a.Name() != "pnpm" {
		t.Errorf("expected pnpm, got %s", a.Name())
	}
}

func TestAdapterLocalPath(t *testing.T) {
	a := &pnpm.Adapter{}
	tests := []struct {
		name string
		want string
	}{
		{"lodash", "node_modules/lodash"},
		{"@scope/pkg", "node_modules/@scope/pkg"},
		{"", "node_modules/"},
	}
	for _, tt := range tests {
		got := a.LocalPath(tt.name)
		if got != tt.want {
			t.Errorf("LocalPath(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// ──────────────────────────────────────────────
// GetTree
// ──────────────────────────────────────────────

func TestGetTree(t *testing.T) {
	t.Run("successful parse", func(t *testing.T) {
		output := `[{"name":"my-project","version":"1.0.0","dependencies":{"lodash":{"from":"lodash","version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}]`
		mockExec(t, output, 0)

		a := &pnpm.Adapter{}
		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tree.Name != "my-project" {
			t.Errorf("expected name=my-project, got %s", tree.Name)
		}
		if tree.Version != "1.0.0" {
			t.Errorf("expected version=1.0.0, got %s", tree.Version)
		}
		dep, ok := tree.Dependencies["lodash"]
		if !ok {
			t.Fatal("missing lodash dependency")
		}
		if dep.Version != "4.17.21" {
			t.Errorf("expected lodash@4.17.21, got %s", dep.Version)
		}
	})

	t.Run("nested dependencies", func(t *testing.T) {
		output := `[{"name":"root","version":"1.0","dependencies":{"express":{"version":"4.18","dependencies":{"accepts":{"version":"1.3.8"}}}}}]`
		mockExec(t, output, 0)

		a := &pnpm.Adapter{}
		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		express, ok := tree.Dependencies["express"]
		if !ok {
			t.Fatal("missing express")
		}
		accepts, ok := express.Dependencies["accepts"]
		if !ok {
			t.Fatal("missing accepts under express")
		}
		if accepts.Version != "1.3.8" {
			t.Errorf("expected accepts@1.3.8, got %s", accepts.Version)
		}
	})

	t.Run("empty array", func(t *testing.T) {
		mockExec(t, `[]`, 0)

		a := &pnpm.Adapter{}
		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tree.Name != "" {
			t.Errorf("expected empty name, got %s", tree.Name)
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		mockExecCheckArgs(t, `[{"name":"t"}]`, 0,
			func(name string, args []string) {
				if name != "pnpm" {
					t.Errorf("expected name=pnpm, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "ls --json --depth Infinity") {
					t.Errorf("expected ls --json --depth Infinity, got %s", got)
				}
			})

		a := &pnpm.Adapter{}
		if _, err := a.GetTree(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("pnpm exits non-zero", func(t *testing.T) {
		mockExec(t, "", 1)

		a := &pnpm.Adapter{}
		_, err := a.GetTree(context.Background())
		if err == nil {
			t.Fatal("expected error when pnpm fails")
		}
	})

	t.Run("invalid JSON from pnpm", func(t *testing.T) {
		mockExec(t, `{not valid json`, 0)

		a := &pnpm.Adapter{}
		_, err := a.GetTree(context.Background())
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

// ──────────────────────────────────────────────
// Install
// ──────────────────────────────────────────────

func TestInstall(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockExec(t, "", 0)

		a := &pnpm.Adapter{}
		if err := a.Install(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		mockExecCheckArgs(t, "", 0,
			func(name string, args []string) {
				if name != "pnpm" {
					t.Errorf("expected name=pnpm, got %s", name)
				}
				if len(args) < 1 || args[0] != "install" {
					t.Errorf("expected install subcommand, got %v", args)
				}
			})

		a := &pnpm.Adapter{}
		if err := a.Install(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("passes extra args", func(t *testing.T) {
		mockExecCheckArgs(t, "", 0,
			func(name string, args []string) {
				got := strings.Join(args, " ")
				if !strings.Contains(got, "lodash express") {
					t.Errorf("expected extra args, got %s", got)
				}
			})

		a := &pnpm.Adapter{}
		if err := a.Install(context.Background(), "lodash", "express"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		mockExec(t, "error message", 1)

		a := &pnpm.Adapter{}
		err := a.Install(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// ──────────────────────────────────────────────
// Resolve
// ──────────────────────────────────────────────

func TestResolve(t *testing.T) {
	t.Run("success creates pnpm-lock.yaml", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		mockExec(t, "", 0)
		if err := os.WriteFile("pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		if err := a.Resolve(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		mockExecCheckArgs(t, "", 0,
			func(name string, args []string) {
				if name != "pnpm" {
					t.Errorf("expected name=pnpm, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "install --lockfile-only") {
					t.Errorf("expected --lockfile-only, got %s", got)
				}
			})

		if err := os.WriteFile("pnpm-lock.yaml", []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		if err := a.Resolve(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("pnpm failure", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		mockExec(t, "", 1)

		a := &pnpm.Adapter{}
		err := a.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing pnpm-lock.yaml after resolve", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		mockExec(t, "", 0)

		a := &pnpm.Adapter{}
		err := a.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error when pnpm-lock.yaml missing")
		}
	})
}

// ──────────────────────────────────────────────
// ParseLockfile (reads pnpm-lock.yaml directly)
// ──────────────────────────────────────────────

func TestParseLockfile(t *testing.T) {
	t.Run("basic packages", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==}
    engines: {node: '>=10'}
    dev: false
  /is-odd/3.0.1:
    resolution: {integrity: sha512-9iEO4qS3oGdE7S9C1rf1XhBfFOrpZTYGy4m1b86N5yI4giR1cOIsfbXkG8N4qLGnZgsMziPD8kDS2YwN7HbQA==}
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}

		byName := map[string]pkgmanager.PackageNode{}
		for _, n := range nodes {
			byName[n.Name] = n
		}

		lodash, ok := byName["lodash"]
		if !ok {
			t.Fatal("missing lodash")
		}
		if lodash.Version != "4.17.21" {
			t.Errorf("lodash version: expected 4.17.21, got %s", lodash.Version)
		}
		if lodash.Integrity != "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==" {
			t.Errorf("lodash integrity mismatch")
		}
		if lodash.Depth != 0 {
			t.Errorf("expected depth 0, got %d", lodash.Depth)
		}

		odd, ok := byName["is-odd"]
		if !ok {
			t.Fatal("missing is-odd")
		}
		if odd.Version != "3.0.1" {
			t.Errorf("is-odd version: expected 3.0.1, got %s", odd.Version)
		}
	})

	t.Run("scoped package", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
packages:
  /@babel/code-frame/7.24.7:
    resolution: {integrity: sha512-BcYH1CVJBO9tvyIZ2jVeXgSIMvGZ2FDRvDdOIVQyuklNKSsx+eppDEBq/g47Ayw+RqNFE+URvOShmf+f/qwAlA==}
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Name != "@babel/code-frame" {
			t.Errorf("expected @babel/code-frame, got %s", nodes[0].Name)
		}
		if nodes[0].Version != "7.24.7" {
			t.Errorf("expected 7.24.7, got %s", nodes[0].Version)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		a := &pnpm.Adapter{}
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error when pnpm-lock.yaml does not exist")
		}
	})

	t.Run("empty packages section", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
packages:
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 0 {
			t.Errorf("expected 0 nodes, got %d", len(nodes))
		}
	})

	t.Run("handles @-separated version (alternative lockfile format)", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-test==}
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Name != "lodash" {
			t.Errorf("expected lodash, got %s", nodes[0].Name)
		}
		if nodes[0].Version != "4.17.21" {
			t.Errorf("expected 4.17.21, got %s", nodes[0].Version)
		}
	})

	t.Run("handles URL-encoded scoped package key", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
packages:
  /@scope%2Fname/1.0.0:
    resolution: {integrity: sha512-test123==}
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Name != "@scope/name" {
			t.Errorf("expected @scope/name, got %s", nodes[0].Name)
		}
		if nodes[0].Version != "1.0.0" {
			t.Errorf("expected 1.0.0, got %s", nodes[0].Version)
		}
	})

	t.Run("no integrity field", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Error(err)
			}
		}()

		lockfile := `lockfileVersion: '9.0'
packages:
  /simple/1.0.0:
    engines: {node: '>=10'}
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := &pnpm.Adapter{}
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Integrity != "" {
			t.Errorf("expected empty integrity, got %s", nodes[0].Integrity)
		}
	})
}

// ──────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────

func TestRegister(t *testing.T) {
	pnpm.Register()
	pm, err := pkgmanager.Get("pnpm")
	if err != nil {
		t.Fatalf("expected pnpm to be registered: %v", err)
	}
	if pm.Name() != "pnpm" {
		t.Errorf("expected name=pnpm, got %s", pm.Name())
	}
}
