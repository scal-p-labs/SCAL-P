package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/audit"
)

func TestLogger(t *testing.T) {
	t.Run("log appends ndjson", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		log := audit.NewLogger(path)

		err := log.Log(context.Background(), []audit.Event{{
			Event:   "test",
			Package: "pkg@1.0",
			Status:  "ok",
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"event":"test"`) {
			t.Errorf("missing event in log: %s", data)
		}
	})

	t.Run("empty events is noop", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		log := audit.NewLogger(path)

		if err := log.Log(context.Background(), nil); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if err := log.Log(context.Background(), []audit.Event{}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file should not exist: %v", err)
		}
	})

	t.Run("creates parent directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nested", "sub", "audit.log")
		log := audit.NewLogger(path)

		err := log.Log(context.Background(), []audit.Event{{
			Event:  "test",
			Status: "ok",
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file should exist: %v", err)
		}
	})

	t.Run("appends to existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		log := audit.NewLogger(path)

		for i := range 3 {
			if err := log.Log(context.Background(), []audit.Event{{
				Event:  "ev",
				Status: "ok",
				Reason: itoa(i),
			}}); err != nil {
				t.Fatal(err)
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d", len(lines))
		}
	})

	t.Run("close returns nil", func(t *testing.T) {
		log := audit.NewLogger(t.TempDir() + "/audit.log")
		if err := log.Close(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}

func itoa(i int) string {
	return string(rune('0' + i))
}
