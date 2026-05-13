package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"scal-p/internal/audit"
	"scal-p/internal/policy"
)

type Violation struct {
	Package string `json:"package"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule"`
}

type AuditSummary struct {
	Verified   int `json:"verified"`
	Mismatched int `json:"mismatched"`
	Missing    int `json:"missing"`
}

type Report struct {
	Version    string       `json:"version"`
	Passed     bool         `json:"passed"`
	Violations []Violation  `json:"violations,omitempty"`
	Audit      AuditSummary `json:"audit"`
}

func FromPolicyViolations(vs []policy.Violation) []Violation {
	out := make([]Violation, 0, len(vs))
	for _, v := range vs {
		out = append(out, Violation{
			Package: v.PackageID,
			Reason:  v.Reason,
			Rule:    v.Rule,
		})
	}
	return out
}

func AuditFromEvents(events []audit.Event) AuditSummary {
	var s AuditSummary
	for _, e := range events {
		switch {
		case e.HashMatch:
			s.Verified++
		case e.Status == "missing" || e.Reason == "missing_lock_entry" || e.Reason == "package_not_installed":
			s.Missing++
		default:
			s.Mismatched++
		}
	}
	return s
}

func Render(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func RenderReport(passed bool, violations []policy.Violation, events []audit.Event) ([]byte, error) {
	r := Report{
		Version:    "0.2",
		Passed:     passed,
		Violations: FromPolicyViolations(violations),
		Audit:      AuditFromEvents(events),
	}
	return Render(r)
}

func WriteReport(path string, passed bool, violations []policy.Violation, events []audit.Event) error {
	data, err := RenderReport(passed, violations, events)
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if path == "" || path == "-" {
		fmt.Println(string(data))
		return nil
	}
	return WriteFile(path, data)
}
