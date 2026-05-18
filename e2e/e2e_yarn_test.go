//go:build e2e

package scalp_test

import (
	"path/filepath"
	"testing"
)

func TestE2E_Yarn_InstallGuarded(t *testing.T) {
	requireYarnBerry(t)
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "yarn", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "yarn", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())
	if !hasNodeModules(dir) {
		t.Fatal("node_modules should exist after install")
	}
}

func TestE2E_Yarn_LockfileInvalid(t *testing.T) {
	requireYarnBerry(t)
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "yarn", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "yarn", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
}
