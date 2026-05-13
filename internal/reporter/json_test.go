package reporter_test

import (
	"testing"

	"scal-p/internal/audit"
	"scal-p/internal/policy"
	"scal-p/internal/reporter"
)

func TestRenderReport_passed(t *testing.T) {
	data, err := reporter.RenderReport(true, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty report")
	}
}

func TestRenderReport_withViolations(t *testing.T) {
	violations := []policy.Violation{
		{PackageID: "evil@1.0", Reason: "denylist_match", Rule: "name:evil"},
	}
	data, err := reporter.RenderReport(false, violations, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty report")
	}
}

func TestAuditFromEvents(t *testing.T) {
	events := []audit.Event{
		{Event: "hash_check", HashMatch: true},
		{Event: "hash_check", HashMatch: true},
		{Event: "hash_check", HashMatch: false},
		{Event: "hash_check", Status: "missing", Reason: "package_not_installed"},
		{Event: "hash_missing", Status: "warn", Reason: "missing_lock_entry"},
	}

	s := reporter.AuditFromEvents(events)
	if s.Verified != 2 {
		t.Errorf("expected 2 verified, got %d", s.Verified)
	}
	if s.Mismatched != 1 {
		t.Errorf("expected 1 mismatched, got %d", s.Mismatched)
	}
	if s.Missing != 2 {
		t.Errorf("expected 2 missing, got %d", s.Missing)
	}
}

func TestWriteReportStdout(t *testing.T) {
	t.Run("empty path writes to stdout", func(t *testing.T) {
		violations := []policy.Violation{
			{PackageID: "test@1.0", Reason: "reason", Rule: "rule"},
		}
		events := []audit.Event{
			{Event: "hash_check", HashMatch: true},
		}
		err := reporter.WriteReport("", false, violations, events)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("dash path writes to stdout", func(t *testing.T) {
		err := reporter.WriteReport("-", true, nil, nil)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}

func TestFromPolicyViolations(t *testing.T) {
	vs := []policy.Violation{
		{PackageID: "a@1", Reason: "r1", Rule: "rule1"},
		{PackageID: "b@2", Reason: "r2", Rule: "rule2"},
	}
	out := reporter.FromPolicyViolations(vs)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Package != "a@1" || out[0].Reason != "r1" {
		t.Errorf("unexpected violation: %+v", out[0])
	}
}
