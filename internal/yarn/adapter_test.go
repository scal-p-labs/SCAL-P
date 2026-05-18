package yarn_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/pkgmanager"
	"scal-p/internal/yarn"
)

func mkAdapter(t *testing.T, stdout string, exitCode int) *yarn.Adapter {
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

	a := yarn.New()
	a.CommandContext = func(_ context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(context.Background(), scriptPath)
	}
	return a
}

func mkAdapterCheckArgs(t *testing.T, stdout string, exitCode int, checkFn func(name string, args []string)) *yarn.Adapter {
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

	a := yarn.New()
	a.CommandContext = func(_ context.Context, name string, arg ...string) *exec.Cmd {
		checkFn(name, arg)
		return exec.CommandContext(context.Background(), scriptPath)
	}
	return a
}

func TestAdapterImplementsInterface(t *testing.T) {
	var _ pkgmanager.PackageManager = &yarn.Adapter{}
}

func TestAdapterName(t *testing.T) {
	a := yarn.New()
	if a.Name() != "yarn" {
		t.Errorf("expected yarn, got %s", a.Name())
	}
}

func TestAdapterLocalPath(t *testing.T) {
	a := yarn.New()
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

func TestGetTree(t *testing.T) {
	t.Run("falls back to CLI when no lockfile", func(t *testing.T) {
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

		a := mkAdapter(t, `{"value":"root@0.0.0","children":{"lodash@npm:4.17.21":{"value":"lodash@npm:4.17.21","children":{}}}}`, 0)
		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := tree.Dependencies["lodash"]; !ok {
			t.Error("missing lodash dependency")
		}
	})

	t.Run("fast path parses lockfile directly", func(t *testing.T) {
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

		lockfile := `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: sha512-test123==
  languageName: node
  linkType: soft

"is-odd@npm:3.0.1":
  version: 3.0.1
  resolution: "is-odd@npm:3.0.1"
  checksum: sha512-abc456==
  languageName: node
  linkType: soft
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
		tree, err := a.GetTree(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Dependencies) != 2 {
			t.Fatalf("expected 2 deps, got %d", len(tree.Dependencies))
		}

		lodash, ok := tree.Dependencies["lodash"]
		if !ok {
			t.Fatal("missing lodash")
		}
		if lodash.Version != "4.17.21" {
			t.Errorf("expected 4.17.21, got %s", lodash.Version)
		}

		odd, ok := tree.Dependencies["is-odd"]
		if !ok {
			t.Fatal("missing is-odd")
		}
		if odd.Version != "3.0.1" {
			t.Errorf("expected 3.0.1, got %s", odd.Version)
		}
	})
}

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
				if name != "yarn" {
					t.Errorf("expected name=yarn, got %s", name)
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

func TestResolve(t *testing.T) {
	t.Run("success with lockfile present", func(t *testing.T) {
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
		if err := os.WriteFile("yarn.lock", []byte(`__metadata:
  version: 6
  cacheKey: 8
`), 0o644); err != nil {
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
				if name != "yarn" {
					t.Errorf("expected name=yarn, got %s", name)
				}
				got := strings.Join(args, " ")
				if !strings.Contains(got, "install --mode=skip-build --immutable") {
					t.Errorf("expected --mode=skip-build --immutable, got %s", got)
				}
			})
		if err := os.WriteFile("yarn.lock", []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := a.Resolve(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("yarn failure", func(t *testing.T) {
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
}

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

		lockfile := `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==
  languageName: node
  linkType: soft

"is-odd@npm:3.0.1":
  version: 3.0.1
  resolution: "is-odd@npm:3.0.1"
  checksum: sha512-9iEO4qS3oGdE7S9C1rf1XhBfFOrpZTYGy4m1b86N5yI4giR1cOIsfbXkG8N4qLGnZgsMziPD8kDS2YwN7HbQA==
  languageName: node
  linkType: soft
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
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

		lockfile := `__metadata:
  version: 6
  cacheKey: 8

"@babel/code-frame@npm:7.24.7":
  version: 7.24.7
  resolution: "@babel/code-frame@npm:7.24.7"
  checksum: sha512-BcYH1CVJBO9tvyIZ2jVeXgSIMvGZ2FDRvDdOIVQyuklNKSsx+eppDEBq/g47Ayw+RqNFE+URvOShmf+f/qwAlA==
  languageName: node
  linkType: soft
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
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

	t.Run("virtual and patch packages skipped", func(t *testing.T) {
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

		lockfile := `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  checksum: sha512-real==
  languageName: node
  linkType: soft

"lodash@virtual:abc#lodash@npm:4.17.21":
  version: 4.17.21
  checksum: sha512-virtual==
  languageName: node
  linkType: soft

"typescript@patch:typescript@npm:5.4.0#builtin.patch":
  version: 5.4.0
  checksum: sha512-patch==
  languageName: node
  linkType: soft
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node (lodash only), got %d", len(nodes))
		}
		if nodes[0].Name != "lodash" {
			t.Errorf("expected lodash, got %s", nodes[0].Name)
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

		a := yarn.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error when yarn.lock does not exist")
		}
	})

	t.Run("rejects Yarn Classic v1", func(t *testing.T) {
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

		lockfile := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#hash"
  integrity sha1-xxxxxx
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
		_, err := a.ParseLockfile(context.Background())
		if err == nil {
			t.Fatal("expected error for Yarn Classic v1 lockfile")
		}
	})

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

		if err := os.WriteFile("yarn.lock", []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 0 {
			t.Errorf("expected 0 nodes, got %d", len(nodes))
		}
	})

	t.Run("deep indentation (peerDependenciesMeta)", func(t *testing.T) {
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

		lockfile := `__metadata:
  version: 6
  cacheKey: 8

"react@npm:18.2.0":
  version: 18.2.0
  resolution: "react@npm:18.2.0"
  dependencies:
    loose-envify: "npm:^1.1.0"
  peerDependenciesMeta:
    react-dom:
      optional: true
  checksum: sha512-reachash==
  languageName: node
  linkType: soft

"loose-envify@npm:1.4.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"
  checksum: sha512-loosehash==
  languageName: node
  linkType: soft
`
		if err := os.WriteFile("yarn.lock", []byte(lockfile), 0o644); err != nil {
			t.Fatal(err)
		}

		a := yarn.New()
		nodes, err := a.ParseLockfile(context.Background())
		if err != nil {
			t.Fatalf("unexpected error with deep indent: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}
		if nodes[0].Name != "react" {
			t.Errorf("expected react, got %s", nodes[0].Name)
		}
		if nodes[0].Version != "18.2.0" {
			t.Errorf("expected 18.2.0, got %s", nodes[0].Version)
		}
	})
}

func TestRegisterYarn(t *testing.T) {
	yarn.Register()
	pm, err := pkgmanager.Get("yarn")
	if err != nil {
		t.Fatalf("expected yarn to be registered: %v", err)
	}
	if pm.Name() != "yarn" {
		t.Errorf("expected name=yarn, got %s", pm.Name())
	}
}
