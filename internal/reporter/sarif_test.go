package reporter

import (
	"encoding/json"
	"testing"

	"scal-p/internal/policy"
)

func TestRenderSarif_Empty(t *testing.T) {
	data := AuditData{
		Version: "v0.2.20",
		Status:  "passed",
		PM:      "npm",
	}

	raw, err := RenderSarif(data)
	if err != nil {
		t.Fatalf("RenderSarif() error = %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "SCAL-P" {
		t.Errorf("expected tool name SCAL-P, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "v0.2.20" {
		t.Errorf("expected version v0.2.20, got %s", run.Tool.Driver.Version)
	}
	if len(run.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(run.Results))
	}
	if !run.Invocations[0].ExecutionSuccessful {
		t.Error("expected execution to be successful")
	}
}

func TestRenderSarif_WithViolations(t *testing.T) {
	violations := []policy.Violation{
		{PackageID: "lodash@4.17.21", Reason: "hash_required: package integrity not in lockfile", Rule: "require_hash:true"},
		{PackageID: "express@4.18.2", Reason: "trust score below minimum", Rule: "min_score:60"},
		{PackageID: "bad-pkg@1.0.0", Reason: "package matched deny rule", Rule: "name:bad-pkg"},
	}

	data := AuditData{
		Timestamp:  "2026-05-20T17:00:00Z",
		Version:    "v0.2.20",
		Status:     "failed",
		PM:         "npm",
		Violations: violations,
	}

	raw, err := RenderSarif(data)
	if err != nil {
		t.Fatalf("RenderSarif() error = %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	run := log.Runs[0]

	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(run.Tool.Driver.Rules))
	}

	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}

	expectedRules := map[string]string{
		"require_hash": "error",
		"min_score":    "error",
		"name":         "error",
	}

	for _, r := range run.Results {
		expectedLevel, ok := expectedRules[r.RuleID]
		if !ok {
			t.Errorf("unexpected rule ID: %s", r.RuleID)
			continue
		}
		if r.Level != expectedLevel {
			t.Errorf("rule %s: expected level %s, got %s", r.RuleID, expectedLevel, r.Level)
		}
		if len(r.Locations) == 0 {
			t.Errorf("rule %s: no locations", r.RuleID)
			continue
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("rule %s: empty URI", r.RuleID)
		}
	}

	if run.Invocations[0].ExecutionSuccessful {
		t.Error("expected execution to be unsuccessful")
	}
}

func TestRenderSarifFromViolations(t *testing.T) {
	violations := []policy.Violation{
		{PackageID: "is-number@7.0.0", Reason: "hash_required", Rule: "require_hash:true"},
	}

	raw, err := RenderSarifFromViolations("v0.2.20", "2026-05-20T17:00:00Z", false, violations)
	if err != nil {
		t.Fatalf("RenderSarifFromViolations() error = %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	run := log.Runs[0]

	if run.Tool.Driver.Version != "v0.2.20" {
		t.Errorf("expected version v0.2.20, got %s", run.Tool.Driver.Version)
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "require_hash" {
		t.Errorf("expected rule require_hash, got %s", run.Results[0].RuleID)
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Error("expected execution to be unsuccessful")
	}
}

func TestNormalizeRuleID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"require_hash:true", "require_hash"},
		{"min_score:60", "min_score"},
		{"max_depth:5", "max_depth"},
		{"name:lodash", "name"},
		{"pattern:*", "pattern"},
		{"allowlist", "allowlist"},
		{"binary_verify", "binary_verify"},
	}

	for _, tc := range tests {
		got := normalizeRuleID(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeRuleID(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"lodash@4.17.21", "lodash"},
		{"@scope/pkg@1.0.0", "@scope/pkg"},
		{"is-number@7.0.0", "is-number"},
		{"no-version", "no-version"},
	}

	for _, tc := range tests {
		got := packageName(tc.input)
		if got != tc.expected {
			t.Errorf("packageName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestRuleLevel(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"require_hash", "error"},
		{"min_score", "error"},
		{"allowlist", "error"},
		{"denylist", "error"},
		{"name", "error"},
		{"pattern", "error"},
		{"max_depth", "warning"},
		{"binary_verify", "error"},
		{"hash_integrity", "error"},
		{"unknown_rule", "error"},
	}

	for _, tc := range tests {
		got := ruleLevel(tc.ruleID)
		if got != tc.expected {
			t.Errorf("ruleLevel(%q) = %q, want %q", tc.ruleID, got, tc.expected)
		}
	}
}

func TestRenderSarif_NoDuplicateRules(t *testing.T) {
	violations := []policy.Violation{
		{PackageID: "a@1.0.0", Reason: "missing hash", Rule: "require_hash:true"},
		{PackageID: "b@2.0.0", Reason: "missing hash", Rule: "require_hash:true"},
		{PackageID: "c@3.0.0", Reason: "missing hash", Rule: "require_hash:true"},
	}

	data := AuditData{
		Version:    "v0.2.20",
		Status:     "failed",
		Violations: violations,
	}

	raw, err := RenderSarif(data)
	if err != nil {
		t.Fatalf("RenderSarif() error = %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (deduplicated), got %d", len(rules))
	}

	if len(log.Runs[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(log.Runs[0].Results))
	}
}

func TestRenderSarif_UsesSchema(t *testing.T) {
	data := AuditData{Version: "v0.2.20", Status: "passed"}
	raw, err := RenderSarif(data)
	if err != nil {
		t.Fatalf("RenderSarif() error = %v", err)
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	schema, ok := rawMap["$schema"].(string)
	if !ok || schema == "" {
		t.Error("missing or empty $schema field")
	}
}

func TestRenderSarif_MaxDepthLevel(t *testing.T) {
	violations := []policy.Violation{
		{PackageID: "deep-dep@5.0.0", Reason: "transitive depth exceeded", Rule: "max_depth:3"},
	}

	data := AuditData{
		Version:    "v0.2.20",
		Status:     "failed",
		Violations: violations,
	}

	raw, err := RenderSarif(data)
	if err != nil {
		t.Fatalf("RenderSarif() error = %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(log.Runs[0].Results))
	}

	result := log.Runs[0].Results[0]
	if result.Level != "warning" {
		t.Errorf("max_depth: expected level 'warning', got '%s'", result.Level)
	}
}
