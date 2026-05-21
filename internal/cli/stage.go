package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/hash"
	"scal-p/internal/policy"
	"scal-p/internal/reporter"
	"scal-p/internal/version"
)

func runStage(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("stage requires a subcommand\n\nUsage: scalp stage verify --stage-id <pkg> [flags]")
	}
	switch args[0] {
	case "verify":
		return runStageVerify(ctx, args[1:])
	default:
		return fmt.Errorf("unknown stage subcommand: %s", args[0])
	}
}

func runStageVerify(ctx context.Context, args []string) error {
	fs := newFlagSet("stage verify")
	stageID := fs.String("stage-id", "", "staged package identifier (e.g. lodash@4.17.21-stage.1)")
	policyPath := fs.String("policy", ".scalp/policy.json", "policy path")
	checksum := fs.String("checksum", "", "expected SHA-512 checksum for the tarball")
	sarifOutput := fs.String("sarif", "", "output path for SARIF report")
	ci := fs.Bool("ci", false, "set enforcement to block on violation")

	if err := parseFlagSet(fs, args); err != nil {
		return err
	}

	if *stageID == "" {
		return fmt.Errorf("--stage-id is required")
	}

	pol, polInfo, err := policy.Load(ctx, *policyPath)
	if err != nil {
		return err
	}

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
	}

	tarballData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read tarball from stdin: %w", err)
	}

	if len(tarballData) == 0 {
		return fmt.Errorf("empty tarball from stdin — pipe npm stage download <stage-id> | scalp stage verify --stage-id <pkg>")
	}

	actualHash := hash.Bytes(tarballData)

	var violations []policy.Violation

	if *checksum != "" {
		if actualHash != *checksum {
			violations = append(violations, policy.Violation{
				PackageID: *stageID,
				Reason:    fmt.Sprintf("hash_mismatch: expected %s, got %s", *checksum, actualHash),
				Rule:      "stage_verify",
			})
		} else {
			slog.Info("tarball checksum verified", "stage_id", *stageID, "hash", actualHash)
		}
	} else {
		slog.Info("no --checksum provided; skipping hash verification", "stage_id", *stageID, "hash", actualHash)
	}

	if denylistCheck(pol, *stageID) {
		violations = append(violations, policy.Violation{
			PackageID: *stageID,
			Reason:    "package matched deny rule",
			Rule:      "denylist",
		})
	}

	auditLogger := audit.NewLogger(".scalp/audit.log")
	defer func() {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("closing audit log", "err", err)
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)
	passed := len(violations) == 0

	if !passed {
		evs := policyViolationEvents(violations)
		if err := auditLogger.Log(ctx, evs); err != nil {
			slog.Warn("logging audit events", "err", err)
		}
	}

	if *sarifOutput != "" {
		data, err := reporter.RenderSarifFromViolations(
			version.Version,
			now,
			passed,
			violations,
		)
		if err != nil {
			slog.Warn("render sarif", "err", err)
		} else if err := reporter.WriteFile(*sarifOutput, data); err != nil {
			slog.Warn("write sarif", "err", err)
		}
	}

	if *ci && !passed {
		return policy.ApplyEnforcement(policy.EnforceBlock, violations)
	}

	if !passed {
		return policy.ApplyEnforcement(pol.Enforcement.OnViolation, violations)
	}

	slog.Info("stage verify passed", "stage_id", *stageID)
	return nil
}

func denylistCheck(pol policy.Policy, stageID string) bool {
	pkgName := stagePkgName(stageID)
	for _, rule := range pol.Packages.Deny {
		if rule.Name != "" && strings.EqualFold(rule.Name, pkgName) {
			return true
		}
		if rule.Pattern != "" && patternMatch(rule.Pattern, pkgName) {
			return true
		}
	}
	return false
}

// stagePkgName extracts the package name from a stage ID like "lodash@4.17.21-stage.1".
func stagePkgName(stageID string) string {
	if idx := strings.LastIndexByte(stageID, '@'); idx != -1 {
		return stageID[:idx]
	}
	return stageID
}

// patternMatch checks if a package name matches a pattern rule.
// Supports * (wildcard), @scope/* (scope matching), and *substr* (contains).
func patternMatch(pattern, pkgName string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "@") && strings.HasSuffix(pattern, "/*") {
		scope := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(pkgName, scope+"/")
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2 {
		sub := pattern[1 : len(pattern)-1]
		return strings.Contains(pkgName, sub)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(pkgName, suffix)
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(pkgName, prefix)
	}
	return pkgName == pattern
}
