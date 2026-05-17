package cli

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/hash"
	"scal-p/internal/policy"
)

type binaryVerifyResult struct {
	filename string
	matched  bool
	expected string
	actual   string
}

// verifyArtifact hashes the artifact and compares against the checksums file.
// It does not handle policy, audit logging, or enforcement — the caller is
// responsible for those.
func verifyArtifact(ctx context.Context, artifactPath, checksumsPath string) (binaryVerifyResult, error) {
	checksums, err := parseChecksums(checksumsPath)
	if err != nil {
		return binaryVerifyResult{}, fmt.Errorf("parse checksums: %w", err)
	}

	filename := filepathBase(artifactPath)
	expectedHash, ok := checksums[filename]
	if !ok {
		return binaryVerifyResult{}, fmt.Errorf("artifact %q not found in checksums file", filename)
	}

	actualHash, err := hash.File(ctx, artifactPath)
	if err != nil {
		return binaryVerifyResult{}, fmt.Errorf("hash artifact: %w", err)
	}

	return binaryVerifyResult{
		filename: filename,
		matched:  expectedHash == actualHash,
		expected: expectedHash,
		actual:   actualHash,
	}, nil
}

func runVerify(ctx context.Context, args []string) error {
	fs := newFlagSet("verify")
	artifact := fs.String("artifact", "", "path to release artifact")
	checksumsFile := fs.String("checksum", "", "path to checksums file")
	policyPath := fs.String("policy", ".scalp/policy.json", "policy path")
	ci := fs.Bool("ci", false, "set enforcement to block on violation")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *artifact == "" {
		return fmt.Errorf("--artifact is required")
	}
	if *checksumsFile == "" {
		return fmt.Errorf("--checksum is required")
	}

	pol, polInfo, err := policy.Load(ctx, *policyPath)
	if err != nil {
		return err
	}

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
	}

	auditLogger := audit.NewLogger(".scalp/audit.log")
	defer func() {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("closing audit log", "err", err)
		}
	}()

	result, err := verifyArtifact(ctx, *artifact, *checksumsFile)
	if err != nil {
		return err
	}

	status := "verified"
	if !result.matched {
		status = "mismatch"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ev := audit.Event{
		Timestamp: now,
		Event:     "binary_verify",
		Package:   result.filename,
		Status:    status,
		HashMatch: result.matched,
	}

	if err := auditLogger.Log(ctx, []audit.Event{ev}); err != nil {
		return fmt.Errorf("log audit: %w", err)
	}

	if result.matched {
		slog.Info("binary verified", "artifact", result.filename, "hash", result.actual)
		return nil
	}

	violations := []policy.Violation{{
		PackageID: result.filename,
		Reason:    fmt.Sprintf("hash_mismatch: expected %s, got %s", result.expected, result.actual),
		Rule:      "binary_verify",
	}}

	enforcement := pol.Enforcement.OnViolation
	if *ci {
		enforcement = policy.EnforceBlock
	}

	return policy.ApplyEnforcement(enforcement, violations)
}

func filepathBase(path string) string {
	if idx := strings.LastIndexAny(path, "/\\"); idx != -1 {
		return path[idx+1:]
	}
	return path
}

func parseChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("checksums file not found: %s", path)
		}
		return nil, fmt.Errorf("open checksums: %w", err)
	}
	defer f.Close() //nolint:errcheck

	checksums := map[string]string{}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			slog.Warn("skipping malformed checksums line", "line", lineNum, "content", line)
			continue
		}
		checksums[parts[1]] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}

	return checksums, nil
}
