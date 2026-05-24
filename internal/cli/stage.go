package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scal-p/internal/audit"
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

	auditLogger := audit.NewLogger(".scalp/audit.log")
	defer func() {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("closing audit log", "err", err)
		}
	}()

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
		if err := auditLogger.Log(ctx, []audit.Event{policyMissingEvent()}); err != nil {
			slog.Warn("logging audit events", "err", err)
		}
	}

	h := sha512.New()
	tee := io.TeeReader(os.Stdin, h)

	tarPkgName, err := extractPkgNameFromTarball(tee)
	if err != nil {
		return fmt.Errorf("read tarball: %w", err)
	}

	actualHash := "sha512-" + base64.StdEncoding.EncodeToString(h.Sum(nil))

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

	expectedName := stagePkgName(*stageID)
	if tarPkgName != "" && !strings.EqualFold(tarPkgName, expectedName) {
		violations = append(violations, policy.Violation{
			PackageID: *stageID,
			Reason:    fmt.Sprintf("stage_id_mismatch: --stage-id name %q does not match tarball package name %q", expectedName, tarPkgName),
			Rule:      "stage_verify",
		})
	}

	denyID := *stageID
	if tarPkgName != "" {
		denyID = tarPkgName
	}
	if denylistCheck(pol, denyID) {
		violations = append(violations, policy.Violation{
			PackageID: *stageID,
			Reason:    "package matched deny rule",
			Rule:      "denylist",
		})
	}

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
			*stageID,
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

const maxPackageJSONSize = 1 << 20 // 1 MB — well beyond any reasonable package.json

func extractPkgNameFromTarball(r io.Reader) (string, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("decompress tarball: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}
		if !strings.HasSuffix(header.Name, "/package.json") {
			continue
		}
		if !filepath.IsLocal(header.Name) {
			return "", fmt.Errorf("non-local path in tarball entry: %s", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxPackageJSONSize))
		if err != nil {
			return "", fmt.Errorf("read package.json: %w", err)
		}
		if len(data) >= maxPackageJSONSize {
			return "", fmt.Errorf("package.json too large (limit %d bytes)", maxPackageJSONSize)
		}
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return "", fmt.Errorf("parse package.json: %w", err)
		}
		return meta.Name, nil
	}

	return "", nil
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

func stagePkgName(stageID string) string {
	if idx := strings.LastIndexByte(stageID, '@'); idx != -1 {
		return stageID[:idx]
	}
	return stageID
}

func patternMatch(pattern, pkgName string) bool {
	pattern = strings.ToLower(pattern)
	pkgName = strings.ToLower(pkgName)

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
