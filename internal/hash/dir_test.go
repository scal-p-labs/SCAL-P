package hash_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/hash"
)

func TestIsDir(t *testing.T) {
	t.Run("existing dir returns true", func(t *testing.T) {
		dir := t.TempDir()
		if !hash.IsDir(dir) {
			t.Error("expected true for existing dir")
		}
	})

	t.Run("file returns false", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "file.txt")
		if err := os.WriteFile(f, []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
		if hash.IsDir(f) {
			t.Error("expected false for file")
		}
	})

	t.Run("non-existent returns false", func(t *testing.T) {
		if hash.IsDir("/nonexistent-path-xyz") {
			t.Error("expected false for non-existent")
		}
	})
}

func TestDir(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		h, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isValidHash(t, h) {
			t.Errorf("invalid hash format: %s", h)
		}
	})

	t.Run("single file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isValidHash(t, h) {
			t.Errorf("invalid hash format: %s", h)
		}
	})

	t.Run("multiple files sorted by name", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("second"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("first"), 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isValidHash(t, h) {
			t.Errorf("invalid hash format: %s", h)
		}
	})

	t.Run("empty files are skipped", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "empty.txt"), []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		emptyDir := t.TempDir()
		emptyHash, _ := hash.Dir(context.Background(), emptyDir)
		if h != emptyHash {
			t.Error("empty file should produce same hash as empty dir")
		}
	})

	t.Run("subdirectories are skipped", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
			t.Fatal(err)
		}
		h, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		emptyHash, _ := hash.Dir(context.Background(), t.TempDir())
		if h != emptyHash {
			t.Error("subdir should be skipped")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		h2, err := hash.Dir(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h1 != h2 {
			t.Error("hash should be deterministic")
		}
	})

	t.Run("non-existent dir", func(t *testing.T) {
		_, err := hash.Dir(context.Background(), "/nonexistent-path-xyz")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func BenchmarkDir(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 100; i++ {
		content := []byte(fmt.Sprintf("package content %d", i))
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d.js", i)), content, 0o644); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hash.Dir(context.Background(), dir); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func isValidHash(t *testing.T, h string) bool {
	t.Helper()
	if len(h) < 10 {
		return false
	}
	if h[:7] != "sha512-" {
		return false
	}
	return true
}
