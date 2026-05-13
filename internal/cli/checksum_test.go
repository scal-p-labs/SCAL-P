package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/cli"
)

func TestChecksum(t *testing.T) {
	t.Run("generates checksums for files", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "a.txt")
		f2 := filepath.Join(dir, "b.txt")
		if err := os.WriteFile(f1, []byte("content a"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f2, []byte("content b"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := cli.Run([]string{"checksum", f1, f2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("writes to --output file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "data.bin")
		out := filepath.Join(dir, "checksums.txt")
		if err := os.WriteFile(f, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := cli.Run([]string{"checksum", "--output", out, f})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(data), "sha512-") {
			t.Errorf("expected sha512- prefix, got %s", string(data))
		}
	})

	t.Run("requires at least one file", func(t *testing.T) {
		err := cli.Run([]string{"checksum"})
		if err == nil {
			t.Fatal("expected error without file args")
		}
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		err := cli.Run([]string{"checksum", "/nonexistent/file"})
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
