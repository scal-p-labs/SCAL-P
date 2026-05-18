//go:build e2e

package scalp_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_AuditReport_Golden(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	reportPath := filepath.Join(dir, "audit-report.md")
	result = runScalp(t, dir, "audit", "--pm", "npm", "--report", reportPath)
	requireExitCode(t, result.exitCode, 0, result.String())

	got := normalizeOutput(readFile(t, reportPath))
	want := normalizeOutput(readGolden(t, filepath.Join("..", "testdata", "golden", "audit-report.md")))
	if got != want {
		t.Fatalf("audit report mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestE2E_CIReport_Golden(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	reportPath := filepath.Join(dir, "ci-report.json")
	result := runScalp(t, dir, "ci", "--pm", "npm", "--output", reportPath)
	requireExitCode(t, result.exitCode, 0, result.String())

	got := normalizeOutput(readFile(t, reportPath))
	want := normalizeOutput(readGolden(t, filepath.Join("..", "testdata", "golden", "ci-report.json")))
	if got != want {
		t.Fatalf("ci report mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestE2E_ChecksumReport_Golden(t *testing.T) {
	file := t.TempDir() + string(filepath.Separator) + "artifact.txt"
	writeFile(t, file, "scalp-checksum-test\n")

	result := runScalp(t, t.TempDir(), "checksum", file)
	requireExitCode(t, result.exitCode, 0, result.String())

	out := strings.TrimSpace(normalizeOutput(result.stdout))
	want := strings.TrimSpace(readGolden(t, filepath.Join("..", "testdata", "golden", "checksum.txt")))
	if out != want {
		t.Fatalf("checksum output mismatch\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}
