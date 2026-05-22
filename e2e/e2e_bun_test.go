//go:build e2e

package scalp_test

import (
	"path/filepath"
	"testing"
)

func TestE2E_Bun_InstallGuarded(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
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

func TestE2E_Bun_Audit_TamperingDetection(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	writeFile(t, filepath.Join(dir, "node_modules", "lodash", "injected.js"), "/* tampered */")
	result = runScalp(t, dir, "audit", "--pm", "bun", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}

func TestE2E_Bun_FallbackPmLs(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	deleteFile(t, filepath.Join(dir, "bun.lock"))

	result = runScalp(t, dir, "audit", "--pm", "bun", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}

func TestE2E_Bun_LockfileInconsistent(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	lfPath := filepath.Join(dir, ".scalp", "lockfile.json")
	lf := readLockfile(t, dir)
	pkgs, ok := lf["packages"].(map[string]any)
	if !ok || len(pkgs) == 0 {
		t.Fatal("lockfile should have packages")
	}
	for key, entry := range pkgs {
		if e, ok := entry.(map[string]any); ok {
			e["integrity"] = "sha512-invalid"
			pkgs[key] = e
			break
		}
	}
	writeJSONFile(t, lfPath, lf)

	result = runScalp(t, dir, "audit", "--pm", "bun", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}

func TestE2E_Bun_LockfileInvalid(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
}
