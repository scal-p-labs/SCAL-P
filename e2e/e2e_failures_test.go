//go:build e2e

package scalp_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_Failure_JSONInvalid(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	lfPath := filepath.Join(dir, ".scalp", "lockfile.json")
	writeFile(t, lfPath, `{invalid json`)

	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
	assertContains(t, strings.ToLower(result.String()), "decode lockfile")
}

func TestE2E_Failure_YAMLInvalid(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	lfPath := filepath.Join(dir, ".scalp", "lockfile.json")
	writeFile(t, lfPath, `{invalid json`)

	result = runScalp(t, dir, "audit", "--pm", "pnpm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
	assertContains(t, strings.ToLower(result.String()), "decode lockfile")
}

func TestE2E_Failure_PolicyDeny(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)
	writePolicy(t, dir, `{
		"version":1,
		"trust":{"mode":"denylist"},
		"packages":{"deny":[{"name":"lodash"}]},
		"enforcement":{"on_violation":"block","default_mode":"guarded"}
	}`)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	if hasNodeModules(dir) {
		t.Fatal("node_modules should not exist")
	}
}

func TestE2E_Failure_IntegrityMismatch(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	lfPath := filepath.Join(dir, ".scalp", "lockfile.json")
	lf := readLockfile(t, dir)
	pkgs, ok := lf["packages"].(map[string]any)
	if !ok || len(pkgs) == 0 {
		t.Fatal("lockfile should have packages")
	}
	for key, entry := range pkgs {
		if e, ok := entry.(map[string]any); ok {
			e["integrity"] = "sha512-tampered"
			pkgs[key] = e
			break
		}
	}
	writeJSONFile(t, lfPath, lf)

	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
	if !eventInAudit(readAuditLog(t, dir), "status", "mismatch") {
		t.Fatalf("expected hash mismatch in audit log")
	}
}

func TestE2E_Failure_MissingNodeModules(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	removeDir(t, filepath.Join(dir, "node_modules"))
	result = runScalp(t, dir, "audit", "--pm", "npm")

	if !eventInAudit(readAuditLog(t, dir), "reason", "package_not_installed") {
		t.Fatalf("expected package_not_installed event in audit log, output:\n%s", result.String())
	}
}
