package npm_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/npm"
	"scal-p/internal/pkgmanager"
)

// mkAdapter returns an *npm.Adapter whose CommandContext runs a mock shell script.
func mkAdapter(t *testing.T, stdout string, exitCode int) *npm.Adapter {
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

	a := npm.New()
	a.CommandContext = func(_ context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(context.Background(), scriptPath)
	}
	return a
}

// mkAdapterCheckArgs is like mkAdapter but also checks the passed command via checkFn.
func mkAdapterCheckArgs(t *testing.T, stdout string, exitCode int, checkFn func(name string, args []string)) *npm.Adapter {
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

	a := npm.New()
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
	var _ pkgmanager.PackageManager = &npm.Adapter{}
}

func TestAdapterName(t *testing.T) {
	a := npm.New()
	if a.Name() != "npm" {
		t.Errorf("expected npm, got %s", a.Name())
	}
}

func TestAdapterLocalPath(t *testing.T) {
	a := npm.New()
	got := a.LocalPath("lodash")
	if got != "node_modules/lodash" {
		t.Errorf("expected node_modules/lodash, got %s", got)
	}
}

// ──────────────────────────────────────────────
// GetTree
// ──────────────────────────────────────────────

func TestGetTree(t *testing.T) {
	t.Run("successful parse", func(t *testing.T) {
		a := mkAdapter(t, `{"name":"root","version":"1.0","dependencies":{"a":{"version":"1.0"}}}`, 0)

		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tree.Name != "root" || tree.Version != "1.0" {
			t.Errorf("unexpected root: %+v", tree)
		}
		if tree.Dependencies["a"].Version != "1.0" {
			t.Errorf("unexpected dep a: %+v", tree.Dependencies["a"])
		}
	})

	t.Run("sends correct command", func(t *testing.T) {
		a := mkAdapterCheckArgs(t, `{"name":"t","dependencies":{}}`, 0,
			func(name string, args []string) {
				if name != "npm" {
					t.Errorf("expected name=npm, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "ls --all --json") {
					t.Errorf("expected ls --all --json, got %s", got)
				}
			})

		if _, err := a.GetTree(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("npm exits non-zero returns partial data", func(t *testing.T) {
		a := mkAdapter(t, `{"name":"partial","version":"1.0"}`, 1)

		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("partial data should still be returned: %v", err)
		}
		if tree.Name != "partial" {
			t.Errorf("expected name=partial, got %s", tree.Name)
		}
	})

	t.Run("invalid JSON from npm", func(t *testing.T) {
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
				if name != "npm" {
					t.Errorf("expected name=npm, got %s", name)
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
	t.Run("success creates package-lock.json", func(t *testing.T) {
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
		if err := os.WriteFile("package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`), 0o644); err != nil {
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
				if name != "npm" {
					t.Errorf("expected name=npm, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "install --package-lock-only") {
					t.Errorf("expected --package-lock-only, got %s", got)
				}
			})

		if err := os.WriteFile("package-lock.json", []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := a.Resolve(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("npm failure", func(t *testing.T) {
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

	t.Run("missing package-lock.json after resolve", func(t *testing.T) {
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
			t.Fatal("expected error when package-lock.json missing")
		}
	})
}

// ──────────────────────────────────────────────
// Flatten — duplicate versions (via pkgmanager)
// ──────────────────────────────────────────────

func TestFlatten_duplicateVersions(t *testing.T) {
	t.Run("lodash@3 + lodash@4 are distinct entries", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{
			Name:    "root",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"lodash": {
					Version: "4.17.21",
					Dependencies: map[string]pkgmanager.DependencyRef{
						"lodash": {Version: "3.10.1"},
					},
				},
			},
		}

		nodes, err := pkgmanager.Flatten(tree)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes for lodash@3 + lodash@4, got %d", len(nodes))
		}

		var foundV3, foundV4 bool
		for _, n := range nodes {
			if n.Name == "lodash" && n.Version == "3.10.1" && n.Depth == 1 {
				foundV3 = true
			}
			if n.Name == "lodash" && n.Version == "4.17.21" && n.Depth == 0 {
				foundV4 = true
			}
		}
		if !foundV3 {
			t.Error("missing lodash@3.10.1 at depth 1")
		}
		if !foundV4 {
			t.Error("missing lodash@4.17.21 at depth 0")
		}
	})

	t.Run("deep chain correctly tracks depth", func(t *testing.T) {
		deps := map[string]pkgmanager.DependencyRef{}
		current := deps
		for _, name := range []string{"a", "b", "c", "d", "e"} {
			next := map[string]pkgmanager.DependencyRef{}
			current[name] = pkgmanager.DependencyRef{Version: "1.0", Dependencies: next}
			current = next
		}

		tree := pkgmanager.DependencyTree{
			Name:         "root",
			Version:      "1.0",
			Dependencies: deps,
		}

		nodes, err := pkgmanager.Flatten(tree)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 5 {
			t.Fatalf("expected 5 nodes, got %d", len(nodes))
		}
		for i, n := range nodes {
			expectedName := string(rune('a' + i))
			if n.Name != expectedName {
				t.Errorf("node[%d]: expected name=%q, got %q", i, expectedName, n.Name)
			}
			if n.Depth != i {
				t.Errorf("node[%d]: expected depth=%d, got %d", i, i, n.Depth)
			}
		}
	})
}

// ──────────────────────────────────────────────
// LocalPath — security edge cases
// ──────────────────────────────────────────────

func TestLocalPath_edgeCases(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"lodash", "node_modules/lodash"},
		{"@scope/pkg", "node_modules/@scope/pkg"},
		{"", "node_modules/"},
		{".", "node_modules/."},
		{"..", "node_modules/.."},
		{"../../etc/passwd", "node_modules/../../etc/passwd"},
		{"a/b/c", "node_modules/a/b/c"},
	}
	for _, tt := range tests {
		got := npm.LocalPath(tt.name)
		if got != tt.want {
			t.Errorf("LocalPath(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// ──────────────────────────────────────────────
// ParsePackageLock
// ──────────────────────────────────────────────

func TestParsePackageLock(t *testing.T) {
	t.Run("v3 lockfile", func(t *testing.T) {
		nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v3.json")
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
		if n, ok := byName["lodash"]; !ok {
			t.Error("missing lodash node")
		} else if n.Version != "4.17.21" {
			t.Errorf("lodash version: expected 4.17.21, got %s", n.Version)
		}
		if n, ok := byName["is-odd"]; !ok {
			t.Error("missing is-odd node")
		} else if n.Version != "3.0.1" {
			t.Errorf("is-odd version: expected 3.0.1, got %s", n.Version)
		}
	})

	t.Run("v2 lockfile with scoped and nested deps", func(t *testing.T) {
		nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v2.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 3 {
			t.Fatalf("expected 3 nodes, got %d", len(nodes))
		}
		byName := map[string]pkgmanager.PackageNode{}
		for _, n := range nodes {
			byName[n.Name] = n
		}
		if n, ok := byName["@scope/name"]; !ok {
			t.Error("missing @scope/name node")
		} else if n.Depth != 0 {
			t.Errorf("@scope/name depth: expected 0, got %d", n.Depth)
		}
		if n, ok := byName["express"]; !ok {
			t.Error("missing express node")
		} else if n.Depth != 0 {
			t.Errorf("express depth: expected 0, got %d", n.Depth)
		}
		if n, ok := byName["accepts"]; !ok {
			t.Error("missing accepts node")
		} else if n.Depth != 1 {
			t.Errorf("accepts depth: expected 1, got %d", n.Depth)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := npm.ParsePackageLock(context.Background(), "nonexistent.json")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestExtractName_nested(t *testing.T) {
	nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v2.json")
	if err != nil {
		t.Fatal(err)
	}

	var nestedFound bool
	for _, n := range nodes {
		if n.Depth == 1 {
			if n.Name != "accepts" {
				t.Errorf("nested dep: expected 'accepts', got '%s'", n.Name)
			}
			nestedFound = true
		}
	}
	if !nestedFound {
		t.Error("no nested dependency found in lockfile-v2.json")
	}
}

// ──────────────────────────────────────────────
// Path traversal edge cases for extractName
// ──────────────────────────────────────────────

func TestExtractName_pathTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	content := `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/..": {"version": "1.0"},
			"node_modules/../../etc": {"version": "1.0"},
			"node_modules/@scope/..": {"version": "1.0"}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	nodes, err := npm.ParsePackageLock(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes from path-traversal lockfile, got %d", len(nodes))
		for _, n := range nodes {
			if strings.Contains(n.Name, "..") || strings.Contains(n.Name, ".") {
				t.Errorf("path traversal name not sanitized: %q", n.Name)
			}
		}
	}
}
