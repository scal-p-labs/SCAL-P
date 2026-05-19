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

// mkAdapter returns an *pnpm.Adapter whose CommandContext runs a mock shell script.
func mkAdapter(t *testing.T, stdout string, exitCode int) *pnpm.Adapter {
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

	a := pnpm.New()
	a.CommandContext = func(_ context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(context.Background(), scriptPath)
	}
	return a
}

// mkAdapterCheckArgs is like mkAdapter but also checks the passed command via checkFn.
func mkAdapterCheckArgs(t *testing.T, stdout string, exitCode int, checkFn func(name string, args []string)) *pnpm.Adapter {
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

	a := pnpm.New()
	a.CommandContext = func(_ context.Context, name string, arg ...string) *exec.Cmd {
		checkFn(name, arg)
		return exec.CommandContext(context.Background(), scriptPath)
	}
	return a
}

// ──────────────────────────────────────────────
// Adapter interface compliance
// ──────────────────────────────────────────────

func TestAdapterImplementsInterface(t *testing.T) {
	var _ pkgmanager.PackageManager = &pnpm.Adapter{}
}

func TestAdapterName(t *testing.T) {
	a := pnpm.New()
	if a.Name() != "pnpm" {
		t.Errorf("expected pnpm, got %s", a.Name())
	}
}

func TestAdapterLocalPath(t *testing.T) {
	a := pnpm.New()
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
		a := mkAdapter(t, output, 0)

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
		a := mkAdapter(t, output, 0)

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
		a := mkAdapter(t, `[]`, 0)

		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tree.Name != "" {
			t.Errorf("expected empty name, got %s", tree.Name)
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		a := mkAdapterCheckArgs(t, `[{"name":"t"}]`, 0,
			func(name string, args []string) {
				if name != "pnpm" {
					t.Errorf("expected name=pnpm, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "ls --json --depth Infinity") {
					t.Errorf("expected ls --json --depth Infinity, got %s", got)
				}
			})

		if _, err := a.GetTree(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("pnpm exits non-zero returns partial data", func(t *testing.T) {
		a := mkAdapter(t, `[{"name":"partial","version":"1.0"}]`, 1)

		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("partial data should still be returned: %v", err)
		}
		if tree.Name != "partial" {
			t.Errorf("expected name=partial, got %s", tree.Name)
		}
	})

	t.Run("invalid JSON from pnpm", func(t *testing.T) {
		a := mkAdapter(t, `{not valid json`, 0)

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
		a := mkAdapter(t, "", 0)

		if err := a.Install(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		a := mkAdapterCheckArgs(t, "", 0,
			func(name string, args []string) {
				if name != "pnpm" {
					t.Errorf("expected name=pnpm, got %s", name)
				}
				if len(args) < 1 || args[0] != "install" {
					t.Errorf("expected install subcommand, got %v", args)
				}
			})

		if err := a.Install(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("passes extra args", func(t *testing.T) {
		a := mkAdapterCheckArgs(t, "", 0,
			func(name string, args []string) {
				got := strings.Join(args, " ")
				if !strings.Contains(got, "lodash express") {
					t.Errorf("expected extra args, got %s", got)
				}
			})

		if err := a.Install(context.Background(), "lodash", "express"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		a := mkAdapter(t, "error message", 1)

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

		a := mkAdapter(t, "", 0)
		if err := os.WriteFile("pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
			t.Fatal(err)
		}

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

		a := mkAdapterCheckArgs(t, "", 0,
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

		a := mkAdapter(t, "", 1)

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

		a := mkAdapter(t, "", 0)

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

		a := pnpm.New()
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

		a := pnpm.New()
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

		a := pnpm.New()
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

		a := pnpm.New()
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

		a := pnpm.New()
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

		a := pnpm.New()
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

		a := pnpm.New()
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
// Tab-indented lockfile parsing
// ──────────────────────────────────────────────

func TestParseLockfile_TabIndented(t *testing.T) {
	t.Run("tab-indented packages", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n\t/lodash/4.17.21:\n\t\tresolution:\n\t\t\tintegrity: sha512-tabtest==\n\t\tdev: false\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
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
		if nodes[0].Integrity != "sha512-tabtest==" {
			t.Errorf("expected sha512-tabtest==, got %s", nodes[0].Integrity)
		}
	})

	t.Run("mixed tabs and spaces", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  /lodash/4.17.21:\n\t\tresolution: {integrity: sha512-mixed==}\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Integrity != "sha512-mixed==" {
			t.Errorf("expected sha512-mixed==, got %s", nodes[0].Integrity)
		}
	})
}

// ──────────────────────────────────────────────
// Multi-line resolution block
// ──────────────────────────────────────────────

func TestParseLockfile_MultiLineResolution(t *testing.T) {
	t.Run("multi-line resolution with integrity", func(t *testing.T) {
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
  /lodash/4.17.21:
    resolution:
      integrity: sha512-multiline-test==
    dev: false
  /is-odd/3.0.1:
    resolution:
      integrity: sha512-odd-test==
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
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
		if lodash.Integrity != "sha512-multiline-test==" {
			t.Errorf("lodash integrity: expected sha512-multiline-test==, got %s", lodash.Integrity)
		}

		odd, ok := byName["is-odd"]
		if !ok {
			t.Fatal("missing is-odd")
		}
		if odd.Integrity != "sha512-odd-test==" {
			t.Errorf("is-odd integrity: expected sha512-odd-test==, got %s", odd.Integrity)
		}
	})

	t.Run("multi-line resolution with resolved URL", func(t *testing.T) {
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
  /lodash/4.17.21:
    resolution:
      integrity: sha512-url-test==
      tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
    dev: false
`
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Integrity != "sha512-url-test==" {
			t.Errorf("expected sha512-url-test==, got %s", nodes[0].Integrity)
		}
	})
}

// ──────────────────────────────────────────────
// Malformed structure validation
// ──────────────────────────────────────────────

func TestParseLockfile_MalformedStructure(t *testing.T) {
	t.Run("unknown indent level", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n   /wrong-indent/1.0.0:\n    resolution: {integrity: sha512-test==}\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error for unknown indent level (3 spaces), got nil")
		}
	})

	t.Run("indent 8 silently skipped (deep nesting)", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  /pkg/1.0.0:\n    resolution: {integrity: sha512-test==}\n    dependencies:\n      sub-dep:\n        version: 2.0.0\n        specifier: ^2.0.0\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Name != "pkg" {
			t.Errorf("expected pkg, got %s", nodes[0].Name)
		}
		if nodes[0].Version != "1.0.0" {
			t.Errorf("expected 1.0.0, got %s", nodes[0].Version)
		}
	})

	t.Run("orphan sub-property silently skipped", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  /pkg/1.0.0:\n    dev: false\n      integrity: sha512-orphan==\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].Integrity != "" {
			t.Errorf("expected empty integrity for orphan sub-property, got %s", nodes[0].Integrity)
		}
	})

	t.Run("empty package key", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  /:\n    resolution: {integrity: sha512-test==}\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error for empty package key, got nil")
		}
	})

	t.Run("double slash in key", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  //b:\n    resolution: {integrity: sha512-test==}\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error for double slash key, got nil")
		}
	})

	t.Run("property outside package entry", func(t *testing.T) {
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

		lockfile := "lockfileVersion: '9.0'\npackages:\n  /pkg/1.0.0:\n    resolution: {integrity: sha512-test==}\n    dev: false\n  resolution:\n"
		if err := os.WriteFile("pnpm-lock.yaml", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error for property outside package entry, got nil")
		}
	})
}

// ──────────────────────────────────────────────
// Empty data
// ──────────────────────────────────────────────

func TestParseLockfile_EmptyData(t *testing.T) {
	t.Run("empty lockfile", func(t *testing.T) {
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

		if err := os.WriteFile("pnpm-lock.yaml", []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}

		a := pnpm.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 0 {
			t.Errorf("expected 0 nodes, got %d", len(nodes))
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
