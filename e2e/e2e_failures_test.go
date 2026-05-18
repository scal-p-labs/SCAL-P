//go:build e2e

package scalp_test

import (
	"path/filepath"
	"testing"
)

func TestE2E_Failure_JSONInvalid(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	assertContains(t, result.String(), "invalid package-lock.json")
}

func TestE2E_Failure_YAMLInvalid(t *testing.T) {
	requireCommand(t, "pnpm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "pnpm", "lockfile-invalid"), dir)

	result := runScalp(t, dir, "install", "--pm", "pnpm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	assertContains(t, result.String(), "pnpm-lock.yaml")
}

func TestE2E_Failure_PolicyDeny(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "policy-deny"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireNonZero(t, result.exitCode, result.String())
	if hasNodeModules(dir) {
		t.Fatal("node_modules should not exist")
	}
}

func TestE2E_Failure_MissingNodeModules(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	removeDir(t, filepath.Join(dir, "node_modules"))
	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}
