package hash_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"scal-p/internal/hash"
)

func TestFile(t *testing.T) {
	t.Run("known content", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/test.txt"
		if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}

		h, err := hash.File(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(h, "sha512-") {
			t.Errorf("expected sha512- prefix, got %s", h)
		}
		if len(h) <= 8 {
			t.Errorf("hash too short: %s", h)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/data.bin"
		if err := os.WriteFile(path, []byte("same content"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, err := hash.File(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		h2, err := hash.File(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if h1 != h2 {
			t.Errorf("expected deterministic hash, got %s vs %s", h1, h2)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/empty"
		if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}

		h, err := hash.File(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(h, "sha512-") {
			t.Errorf("expected sha512- prefix, got %s", h)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := hash.File(context.Background(), "/nonexistent/path")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
