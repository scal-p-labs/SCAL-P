package policy_test

import (
	"errors"
	"strings"
	"testing"

	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
)

func node(name, version string, depth int) pkgmanager.PackageNode {
	return pkgmanager.PackageNode{Name: name, Version: version, Depth: depth}
}

func TestEvaluate_auditOnly(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustAuditOnly

	nodes := []pkgmanager.PackageNode{node("evil", "1.0", 0)}
	violations, err := policy.Evaluate(pol, nodes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations in audit-only, got %d", len(violations))
	}
}

func TestEvaluate_allowlist(t *testing.T) {
	tests := []struct {
		name     string
		pol      policy.Policy
		nodes    []pkgmanager.PackageNode
		violates int
	}{
		{
			name:     "allowed exact",
			pol:      allowlistPol([]policy.PackageRule{{Name: "lodash"}, {Pattern: "@trusted/*"}}),
			nodes:    []pkgmanager.PackageNode{node("lodash", "4.17", 0)},
			violates: 0,
		},
		{
			name:     "allowed scoped",
			pol:      allowlistPol([]policy.PackageRule{{Name: "lodash"}, {Pattern: "@trusted/*"}}),
			nodes:    []pkgmanager.PackageNode{node("@trusted/foo", "1.0", 0)},
			violates: 0,
		},
		{
			name:     "blocked unknown",
			pol:      allowlistPol([]policy.PackageRule{{Name: "lodash"}, {Pattern: "@trusted/*"}}),
			nodes:    []pkgmanager.PackageNode{node("evil", "1.0", 0)},
			violates: 1,
		},
		{
			name:     "mixed",
			pol:      allowlistPol([]policy.PackageRule{{Name: "lodash"}, {Pattern: "@trusted/*"}}),
			nodes:    []pkgmanager.PackageNode{node("lodash", "4.17", 0), node("evil", "1.0", 0)},
			violates: 1,
		},
		{
			name:     "empty allowlist blocks all",
			pol:      allowlistPol(nil),
			nodes:    []pkgmanager.PackageNode{node("lodash", "4.17", 0)},
			violates: 1,
		},
		{
			name:     "empty nodes",
			pol:      allowlistPol([]policy.PackageRule{{Name: "lodash"}}),
			nodes:    nil,
			violates: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := policy.Evaluate(tt.pol, tt.nodes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(violations) != tt.violates {
				t.Errorf("expected %d violations, got %d: %+v", tt.violates, len(violations), violations)
			}
		})
	}
}

func allowlistPol(rules []policy.PackageRule) policy.Policy {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustAllowlist
	pol.Packages.Allow = rules
	return pol
}

func TestEvaluate_denylist(t *testing.T) {
	tests := []struct {
		name     string
		pol      policy.Policy
		nodes    []pkgmanager.PackageNode
		violates int
	}{
		{
			name:     "allowed not denied",
			pol:      denylistPol([]policy.PackageRule{{Name: "evil"}, {Pattern: "*-free"}}),
			nodes:    []pkgmanager.PackageNode{node("lodash", "4.17", 0)},
			violates: 0,
		},
		{
			name:     "exact deny",
			pol:      denylistPol([]policy.PackageRule{{Name: "evil"}, {Pattern: "*-free"}}),
			nodes:    []pkgmanager.PackageNode{node("evil", "1.0", 0)},
			violates: 1,
		},
		{
			name:     "pattern deny",
			pol:      denylistPol([]policy.PackageRule{{Name: "evil"}, {Pattern: "*-free"}}),
			nodes:    []pkgmanager.PackageNode{node("trial-free", "1.0", 0)},
			violates: 1,
		},
		{
			name:     "mixed",
			pol:      denylistPol([]policy.PackageRule{{Name: "evil"}, {Pattern: "*-free"}}),
			nodes:    []pkgmanager.PackageNode{node("lodash", "4.17", 0), node("evil", "1.0", 0)},
			violates: 1,
		},
		{
			name:     "empty denylist allows all",
			pol:      denylistPol(nil),
			nodes:    []pkgmanager.PackageNode{node("evil", "1.0", 0)},
			violates: 0,
		},
		{
			name:     "empty nodes",
			pol:      denylistPol([]policy.PackageRule{{Name: "evil"}}),
			nodes:    nil,
			violates: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := policy.Evaluate(tt.pol, tt.nodes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(violations) != tt.violates {
				t.Errorf("expected %d violations, got %d: %+v", tt.violates, len(violations), violations)
			}
		})
	}
}

func denylistPol(rules []policy.PackageRule) policy.Policy {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustDenylist
	pol.Packages.Deny = rules
	return pol
}

func TestEvaluate_transitiveDepth(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustAllowlist
	pol.Packages.Allow = []policy.PackageRule{{Pattern: "*"}}
	pol.Transitive.MaxDepth = 2

	tests := []struct {
		name     string
		depth    int
		violates bool
	}{
		{"root", 0, false},
		{"direct dep", 1, false},
		{"transitive-2", 2, false},
		{"transitive-3", 3, true},
		{"deep", 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := []pkgmanager.PackageNode{node("pkg", "1.0", tt.depth)}
			violations, err := policy.Evaluate(pol, nodes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.violates {
				t.Errorf("depth=%d: expected violates=%v, got violations=%d", tt.depth, tt.violates, len(violations))
			}
		})
	}
}

func TestEvaluate_transitiveDepthZero(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustAllowlist
	pol.Packages.Allow = []policy.PackageRule{{Pattern: "*"}}
	pol.Transitive.MaxDepth = 0

	nodes := []pkgmanager.PackageNode{node("deep", "1.0", 100)}
	violations, err := policy.Evaluate(pol, nodes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations when MaxDepth=0, got %d", len(violations))
	}
}

func TestEvaluate_edgeCases(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustDenylist
	pol.Packages.Deny = []policy.PackageRule{{Name: "evil"}}

	t.Run("empty version", func(t *testing.T) {
		nodes := []pkgmanager.PackageNode{node("evil", "", 0)}
		violations, err := policy.Evaluate(pol, nodes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
		if !strings.Contains(violations[0].PackageID, "@") {
			t.Errorf("expected @ in PackageID, got %s", violations[0].PackageID)
		}
	})

	t.Run("nil nodes", func(t *testing.T) {
		violations, err := policy.Evaluate(pol, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for nil, got %d", len(violations))
		}
	})
}

// ──────────────────────────────────────────────
// Adversarial scenarios for Evaluate
// ──────────────────────────────────────────────

func TestEvaluate_duplicateVersions(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustDenylist
	pol.Packages.Deny = []policy.PackageRule{
		{Name: "lodash"},
	}

	nodes := []pkgmanager.PackageNode{
		{Name: "lodash", Version: "4.17.21", Depth: 0},
		{Name: "lodash", Version: "3.10.1", Depth: 1},
	}

	violations, err := policy.Evaluate(pol, nodes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 2 {
		t.Errorf("expected 2 violations (one per version), got %d: %+v", len(violations), violations)
	}
}

func TestEvaluate_denylistBlocksMultiplePatterns(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Trust.Mode = policy.TrustDenylist
	pol.Packages.Deny = []policy.PackageRule{
		{Name: "a"},
		{Name: "b"},
		{Pattern: "*-evil"},
	}

	nodes := []pkgmanager.PackageNode{
		{Name: "a", Version: "1.0", Depth: 0},
		{Name: "b", Version: "2.0", Depth: 1},
		{Name: "c-evil", Version: "3.0", Depth: 2},
		{Name: "safe", Version: "1.0", Depth: 0},
	}

	violations, err := policy.Evaluate(pol, nodes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 3 {
		t.Errorf("expected 3 violations (a, b, c-evil), got %d: %+v", len(violations), violations)
	}
}
func TestApplyEnforcement(t *testing.T) {
	violations := []policy.Violation{{PackageID: "evil@1.0", Reason: "denylist_match", Rule: "name:evil"}}

	t.Run("block returns error", func(t *testing.T) {
		err := policy.ApplyEnforcement(policy.EnforceBlock, violations)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "evil@1.0") {
			t.Errorf("error should mention package: %v", err)
		}
	})

	t.Run("warn returns nil", func(t *testing.T) {
		err := policy.ApplyEnforcement(policy.EnforceWarn, violations)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("log returns nil", func(t *testing.T) {
		err := policy.ApplyEnforcement(policy.EnforceLog, violations)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("empty violations returns nil", func(t *testing.T) {
		err := policy.ApplyEnforcement(policy.EnforceBlock, nil)
		if err != nil {
			t.Errorf("expected nil for empty violations, got %v", err)
		}
		err = policy.ApplyEnforcement(policy.EnforceBlock, []policy.Violation{})
		if err != nil {
			t.Errorf("expected nil for empty violations, got %v", err)
		}
	})

	t.Run("unknown mode treated as warn", func(t *testing.T) {
		err := policy.ApplyEnforcement("invalid-mode", violations)
		if err != nil {
			t.Errorf("expected nil for unknown mode, got %v", err)
		}
	})

	t.Run("block error message", func(t *testing.T) {
		err := policy.ApplyEnforcement(policy.EnforceBlock, violations)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, err) {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
