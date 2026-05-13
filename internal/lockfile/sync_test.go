package lockfile_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/lockfile"
	"scal-p/internal/npm"
	"scal-p/internal/pkgmanager"
)

func chdir(t *testing.T, dir string) string {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return old
}

func restoreWd(t *testing.T, old string) {
	t.Helper()
	if err := os.Chdir(old); err != nil {
		t.Error(err)
	}
}

// npmPM returns an npm adapter for use in tests.
func npmPM() pkgmanager.PackageManager {
	return &npm.Adapter{}
}

func TestSyncWithTree(t *testing.T) {
	t.Run("syncs packages from tree", func(t *testing.T) {
		dir := t.TempDir()
		old := chdir(t, dir)
		defer restoreWd(t, old)

		pkgDir := filepath.Join("node_modules", "mypkg")
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte("module.exports=1"), 0o644); err != nil {
			t.Fatal(err)
		}

		tree := pkgmanager.DependencyTree{
			Name:    "test",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"mypkg": {Version: "1.0", Resolved: "https://example.com/mypkg.tgz"},
			},
		}

		lf := newLockfile("")
		events, err := lockfile.SyncWithTree(context.Background(), &lf, tree, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
		entry, ok := lf.Packages["mypkg@1.0"]
		if !ok {
			t.Fatal("expected mypkg@1.0 in lockfile")
		}
		if entry.Resolved != "https://example.com/mypkg.tgz" {
			t.Errorf("unexpected resolved: %s", entry.Resolved)
		}
		if entry.Integrity == "" {
			t.Error("expected non-empty integrity hash")
		}
	})

	t.Run("missing package dir is skipped", func(t *testing.T) {
		dir := t.TempDir()
		old := chdir(t, dir)
		defer restoreWd(t, old)

		tree := pkgmanager.DependencyTree{
			Name:    "test",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"ghost": {Version: "2.0"},
			},
		}

		lf := newLockfile("")
		events, err := lockfile.SyncWithTree(context.Background(), &lf, tree, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 0 {
			t.Errorf("expected 0 events for missing dir, got %d", len(events))
		}
	})

	t.Run("empty tree", func(t *testing.T) {
		lf := newLockfile("")
		events, err := lockfile.SyncWithTree(context.Background(), &lf, pkgmanager.DependencyTree{}, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 0 {
			t.Errorf("expected 0 events, got %d", len(events))
		}
	})
}

func TestVerifyAgainstTree(t *testing.T) {
	t.Run("verified hash produces no violations", func(t *testing.T) {
		dir := t.TempDir()
		old := chdir(t, dir)
		defer restoreWd(t, old)

		pkgDir := filepath.Join("node_modules", "pkg")
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "a.js"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		tree := pkgmanager.DependencyTree{
			Name:    "test",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"pkg": {Version: "1.0"},
			},
		}

		lf := newLockfile("")
		if _, err := lockfile.SyncWithTree(context.Background(), &lf, tree, npmPM()); err != nil {
			t.Fatal(err)
		}

		violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %+v", len(violations), violations)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
	})

	t.Run("missing lock entry is violation", func(t *testing.T) {
		dir := t.TempDir()
		old := chdir(t, dir)
		defer restoreWd(t, old)

		pkgDir := filepath.Join("node_modules", "unknown")
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "a.js"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		tree := pkgmanager.DependencyTree{
			Name:    "test",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"unknown": {Version: "1.0"},
			},
		}

		lf := newLockfile("")
		violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Reason != "missing_lock_entry" {
			t.Errorf("expected missing_lock_entry, got %s", violations[0].Reason)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
	})

	t.Run("missing package dir is now a violation", func(t *testing.T) {
		lf := newLockfile("")
		lf.Packages["ghost@1.0"] = newEntry("url", "hash", "now")

		tree := pkgmanager.DependencyTree{
			Name:    "test",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"ghost": {Version: "1.0"},
			},
		}

		violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Errorf("expected 1 violation for missing dir, got %d", len(violations))
		}
		if violations[0].Reason != "package_not_installed" {
			t.Errorf("expected package_not_installed, got %s", violations[0].Reason)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
	})
}

// Tests for adversarial scenarios.
//
// These tests simulate real-world attacks that SCAL-P must detect:
//   - Hash tampering (lockfile hash != real content)
//   - Modification after synchronization
//   - Package deletion after installation
//   - Lockfile metadata alteration

func TestAdversarial_hashTampered(t *testing.T) {
	dir := t.TempDir()
	old := chdir(t, dir)
	defer restoreWd(t, old)

	pkgDir := filepath.Join("node_modules", "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte("real content"), 0o644); err != nil {
		t.Fatal(err)
	}

	tree := pkgmanager.DependencyTree{
		Name:    "test",
		Version: "1.0",
		Dependencies: map[string]pkgmanager.DependencyRef{
			"pkg": {Version: "1.0"},
		},
	}

	lf := newLockfile("")
	lf.Packages["pkg@1.0"] = newEntry("url", "sha512-fakehashthatexistsonlyonpaper", "earlier")

	violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Reason != "hash_mismatch" {
		t.Errorf("expected hash_mismatch, got %s", violations[0].Reason)
	}
	if len(events) > 0 && events[0].HashMatch {
		t.Error("expected HashMatch=false for tampered package")
	}
}

func TestAdversarial_modifiedAfterSync(t *testing.T) {
	dir := t.TempDir()
	old := chdir(t, dir)
	defer restoreWd(t, old)

	pkgDir := filepath.Join("node_modules", "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "a.js"), []byte("clean"), 0o644); err != nil {
		t.Fatal(err)
	}

	tree := pkgmanager.DependencyTree{
		Name:    "test",
		Version: "1.0",
		Dependencies: map[string]pkgmanager.DependencyRef{
			"pkg": {Version: "1.0"},
		},
	}

	lf := newLockfile("")
	if _, err := lockfile.SyncWithTree(context.Background(), &lf, tree, npmPM()); err != nil {
		t.Fatal(err)
	}

	// Attack: modify the file after sync
	if err := os.WriteFile(filepath.Join(pkgDir, "a.js"), []byte("injected backdoor"), 0o644); err != nil {
		t.Fatal(err)
	}

	violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation after modification, got %d", len(violations))
	}
	if violations[0].Reason != "hash_mismatch" {
		t.Errorf("expected hash_mismatch, got %s", violations[0].Reason)
	}
	if len(events) > 0 && events[0].HashMatch {
		t.Error("expected HashMatch=false after modification")
	}
}

func TestAdversarial_packageDeleted(t *testing.T) {
	dir := t.TempDir()
	old := chdir(t, dir)
	defer restoreWd(t, old)

	lf := newLockfile("")
	lf.Packages["deleted@1.0"] = newEntry("url", "sha512-abc", "past")

	tree := pkgmanager.DependencyTree{
		Name:    "test",
		Version: "1.0",
		Dependencies: map[string]pkgmanager.DependencyRef{
			"deleted": {Version: "1.0"},
		},
	}

	violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for deleted package, got %d", len(violations))
	}
	if violations[0].Reason != "package_not_installed" {
		t.Errorf("expected package_not_installed, got %s", violations[0].Reason)
	}
	if len(events) != 1 || events[0].Status != "missing" {
		t.Errorf("expected 1 event with status=missing, got %+v", events)
	}
}

func TestAdversarial_lockfileHashWrong(t *testing.T) {
	dir := t.TempDir()
	old := chdir(t, dir)
	defer restoreWd(t, old)

	pkgDir := filepath.Join("node_modules", "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "a.js"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	tree := pkgmanager.DependencyTree{
		Name:    "test",
		Version: "1.0",
		Dependencies: map[string]pkgmanager.DependencyRef{
			"pkg": {Version: "1.0"},
		},
	}

	lf := newLockfile("")
	lf.Packages["pkg@1.0"] = newEntry("url", "sha512-nottheactualhash", "now")

	violations, events, err := lockfile.VerifyAgainstTree(context.Background(), &lf, tree, npmPM())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation for wrong lockfile hash, got %d", len(violations))
	}
	if violations[0].Reason != "hash_mismatch" {
		t.Errorf("expected hash_mismatch, got %s", violations[0].Reason)
	}
	if len(events) > 0 && events[0].HashMatch {
		t.Error("expected HashMatch=false when lockfile hash is wrong")
	}
}
