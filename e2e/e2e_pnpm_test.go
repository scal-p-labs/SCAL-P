//go:build e2e

package scalp_test

import (
	"path/filepath"
	"testing"
)

func TestE2E_Pnpm_InstallGuarded(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())
	if !hasNodeModules(dir) {
		t.Fatal("node_modules should exist after install")
	}
	lf := readLockfile(t, dir)
	if lf == nil {
		t.Fatal("lockfile should exist after install")
	}
	assertLockfileHasPackage(t, lf, "lodash")
}

func TestE2E_Pnpm_PolicyDeny_Blocks(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "policy-deny"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	if hasNodeModules(dir) {
		t.Fatal("node_modules should not exist (blocked before install)")
	}
}

func TestE2E_Pnpm_Audit_Tamper(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	writeFile(t, filepath.Join(dir, "node_modules", "lodash", "injected.js"), "/* tampered */")
	result = runScalp(t, dir, "audit", "--pm", "pnpm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}

func TestE2E_Pnpm_LockfileInvalid(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	assertContains(t, result.String(), "pnpm-lock.yaml")
}
