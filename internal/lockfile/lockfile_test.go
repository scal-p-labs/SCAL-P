package lockfile_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/lockfile"
)

func newLockfile(ts string) lockfile.Lockfile {
	return lockfile.Lockfile{
		LockVersion: 2,
		GeneratedAt: ts,
		Packages:    map[string]lockfile.LockEntry{},
	}
}

func newEntry(resolved, integrity, verifiedAt string) lockfile.LockEntry {
	return lockfile.LockEntry{
		Resolved:   resolved,
		Integrity:  integrity,
		VerifiedAt: verifiedAt,
	}
}

func TestLoad(t *testing.T) {
	t.Run("file not found returns default", func(t *testing.T) {
		lf, err := lockfile.Load(context.Background(), "/nonexistent/lockfile.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lf.LockVersion != 2 {
			t.Errorf("expected LockVersion=2, got %d", lf.LockVersion)
		}
		if lf.Packages == nil {
			t.Error("expected non-nil Packages map")
		}
		if len(lf.Packages) != 0 {
			t.Errorf("expected empty Packages, got %d", len(lf.Packages))
		}
	})

	t.Run("valid json loads correctly", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lockfile.json")
		if err := os.WriteFile(path, []byte(`{"lockVersion":2,"packages":{"lodash@4.0":{"resolved":"url","integrity":"hash","verifiedAt":"now"}}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		lf, err := lockfile.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lf.Packages) != 1 {
			t.Errorf("expected 1 package, got %d", len(lf.Packages))
		}
		if lf.Packages["lodash@4.0"].Integrity != "hash" {
			t.Errorf("unexpected integrity: %s", lf.Packages["lodash@4.0"].Integrity)
		}
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lockfile.json")
		if err := os.WriteFile(path, []byte(`{bad`), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := lockfile.Load(context.Background(), path)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("nil packages normalized", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lockfile.json")
		if err := os.WriteFile(path, []byte(`{"lockVersion":2}`), 0o644); err != nil {
			t.Fatal(err)
		}

		lf, err := lockfile.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lf.Packages == nil {
			t.Error("expected non-nil Packages")
		}
	})
}

func TestSave(t *testing.T) {
	t.Run("saves and loads back", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sub", "lockfile.json")

		lf := newLockfile("now")
		lf.Packages["pkg@1.0"] = newEntry("url", "hash", "now")

		if err := lockfile.Save(context.Background(), path, &lf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		loaded, err := lockfile.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if loaded.Packages["pkg@1.0"].Integrity != "hash" {
			t.Errorf("round-trip failed: %+v", loaded.Packages["pkg@1.0"])
		}
	})

	t.Run("creates parent dir", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "a", "b", "lockfile.json")
		lf := newLockfile("now")

		if err := lockfile.Save(context.Background(), path, &lf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file should exist: %v", err)
		}
	})
}
