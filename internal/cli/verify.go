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

func runVerify(args []string) error {
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

	ctx := context.Background()
	pol, _, err := policy.Load(ctx, *policyPath)
	if err != nil {
		return err
	}

	auditLogger := audit.NewLogger(".scalp/audit.log")
	defer func() {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("closing audit log", "err", err)
		}
	}()

	checksums, err := parseChecksums(*checksumsFile)
	if err != nil {
		return fmt.Errorf("parse checksums: %w", err)
	}

	filename := filepathBase(*artifact)
	expectedHash, ok := checksums[filename]
	if !ok {
		return fmt.Errorf("artifact %q not found in checksums file", filename)
	}

	actualHash, err := hash.File(ctx, *artifact)
	if err != nil {
		return fmt.Errorf("hash artifact: %w", err)
	}

	match := expectedHash == actualHash
	status := "verified"
	if !match {
		status = "mismatch"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ev := audit.Event{
		Timestamp: now,
		Event:     "binary_verify",
		Package:   filename,
		Status:    status,
		HashMatch: match,
	}

	if err := auditLogger.Log(ctx, []audit.Event{ev}); err != nil {
		return fmt.Errorf("log audit: %w", err)
	}

	if match {
		slog.Info("binary verified", "artifact", filename, "hash", actualHash)
		return nil
	}

	violations := []policy.Violation{{
		PackageID: filename,
		Reason:    fmt.Sprintf("hash_mismatch: expected %s, got %s", expectedHash, actualHash),
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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		checksums[parts[1]] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}

	return checksums, nil
}
