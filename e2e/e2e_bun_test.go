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
}

func TestE2E_Bun_LockfileInvalid(t *testing.T) {
	requireCommand(t, "bun")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "bun", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "bun", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
}
