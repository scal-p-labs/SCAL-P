package ioutil_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/ioutil"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Run("writes file correctly", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.txt")

		if err := ioutil.WriteFileAtomic(path, []byte("hello"), 0o644); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "hello" {
			t.Errorf("expected 'hello', got '%s'", string(data))
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.txt")

		if err := ioutil.WriteFileAtomic(path, []byte("first"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFileAtomic(path, []byte("second"), 0o644); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "second" {
			t.Errorf("expected 'second', got '%s'", string(data))
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "a", "b", "test.txt")

		if err := ioutil.WriteFileAtomic(path, []byte("nested"), 0o644); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file to exist: %v", err)
		}
	})

	t.Run("default permission without perm arg", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "default.txt")

		if err := ioutil.WriteFileAtomic(path, []byte("default")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "default" {
			t.Errorf("expected 'default', got '%s'", string(data))
		}
	})

	t.Run("no .tmp file left after success", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "clean.txt")

		if err := ioutil.WriteFileAtomic(path, []byte("clean")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("expected .tmp file to be removed, stat err=%v", err)
		}
	})

	t.Run("large content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "large.txt")

		data := []byte(strings.Repeat("A", 1024*1024)) // 1 MB
		if err := ioutil.WriteFileAtomic(path, data); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		read, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(read) != len(data) {
			t.Errorf("expected %d bytes, got %d", len(data), len(read))
		}
	})
}
