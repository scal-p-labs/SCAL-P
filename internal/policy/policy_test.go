package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/policy"
)

func TestLoad(t *testing.T) {
	t.Run("file not found returns default", func(t *testing.T) {
		pol, info, err := policy.Load(context.Background(), "/nonexistent/policy.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !info.MissingPolicy {
			t.Error("expected MissingPolicy=true")
		}
		if pol.Version != 1 {
			t.Errorf("expected Version=1, got %d", pol.Version)
		}
	})

	t.Run("valid json loads correctly", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"trust":{"mode":"denylist"},"packages":{"deny":[{"name":"evil"}]},"enforcement":{"on_violation":"block","default_mode":"guarded"}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		pol, info, err := policy.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.MissingPolicy {
			t.Error("expected MissingPolicy=false")
		}
		if pol.Trust.Mode != "denylist" {
			t.Errorf("expected denylist, got %s", pol.Trust.Mode)
		}
		if len(pol.Packages.Deny) != 1 || pol.Packages.Deny[0].Name != "evil" {
			t.Errorf("unexpected deny rules: %+v", pol.Packages.Deny)
		}
		if pol.Enforcement.OnViolation != "block" {
			t.Errorf("expected block, got %s", pol.Enforcement.OnViolation)
		}
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
			t.Fatal(err)
		}

		_, _, err := policy.Load(context.Background(), path)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing fields default", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}

		pol, info, err := policy.Load(context.Background(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.MissingPolicy {
			t.Error("expected MissingPolicy=false")
		}
		if pol.Trust.Mode != "audit-only" {
			t.Errorf("expected audit-only, got %s", pol.Trust.Mode)
		}
		if pol.Enforcement.OnViolation != "warn" {
			t.Errorf("expected warn, got %s", pol.Enforcement.OnViolation)
		}
		if pol.Enforcement.DefaultMode != "passthrough" {
			t.Errorf("expected passthrough, got %s", pol.Enforcement.DefaultMode)
		}
	})
}

func TestDefaultPolicy(t *testing.T) {
	pol := policy.DefaultPolicy()
	if pol.Version != 1 {
		t.Errorf("expected Version=1, got %d", pol.Version)
	}
	if pol.Trust.Mode != "audit-only" {
		t.Errorf("expected audit-only, got %s", pol.Trust.Mode)
	}
	if pol.Enforcement.OnViolation != "warn" {
		t.Errorf("expected warn, got %s", pol.Enforcement.OnViolation)
	}
	if pol.Enforcement.DefaultMode != "passthrough" {
		t.Errorf("expected passthrough, got %s", pol.Enforcement.DefaultMode)
	}
}
