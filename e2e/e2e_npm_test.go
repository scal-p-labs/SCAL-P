//go:build e2e

package scalp_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_NPM_InstallGuarded_BlockBeforeInstall(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "policy-deny"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")

	requireNonZero(t, result.exitCode, result.String())
	if hasNodeModules(dir) {
		t.Fatal("node_modules should not exist (blocked before install)")
	}
	if !eventInAudit(readAuditLog(t, dir), "event", "policy_violation") {
		t.Fatalf("expected policy_violation in audit log")
	}
}

func TestE2E_NPM_InstallGuarded_HappyPath(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")

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

func TestE2E_NPM_Audit_TamperingDetection(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	lodashDir := filepath.Join(dir, "node_modules", "lodash")
	entries, err := os.ReadDir(lodashDir)
	if err != nil {
		t.Fatal(err)
	}
	var tampered bool
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		fpath := filepath.Join(lodashDir, e.Name())
		info, err := e.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		orig, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		if err := os.WriteFile(fpath, append(orig, []byte("\n// TAMPERED\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		tampered = true
		break
	}
	if !tampered {
		t.Fatal("could not find a file to tamper in lodash")
	}

	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
	if !eventInAudit(readAuditLog(t, dir), "status", "mismatch") {
		t.Fatalf("expected hash mismatch in audit log")
	}
}

func TestE2E_NPM_Audit_MissingPackage(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "simple"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())

	removeDir(t, filepath.Join(dir, "node_modules", "lodash"))
	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
	if !eventInAudit(readAuditLog(t, dir), "status", "missing") {
		t.Fatalf("expected missing package in audit log")
	}
}

func TestE2E_NPM_AuditOnly_AllowsInstall(t *testing.T) {
	requireCommand(t, "npm")
	dir := t.TempDir()
	copyFixture(t, filepath.Join("..", "testdata", "npm", "policy-audit-only"), dir)

	result := runScalp(t, dir, "install", "--pm", "npm", "--guarded")
	requireExitCode(t, result.exitCode, 0, result.String())
	if !hasNodeModules(dir) {
		t.Fatal("node_modules should exist in audit-only mode")
	}
}

func TestE2E_NPM_LockfileInconsistent(t *testing.T) {
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
			e["integrity"] = "sha512-invalid"
			pkgs[key] = e
			break
		}
	}
	writeJSONFile(t, lfPath, lf)

	result = runScalp(t, dir, "audit", "--pm", "npm", "--ci")
	requireNonZero(t, result.exitCode, result.String())
}

func TestE2E_NPM_Verify_BinaryMismatch(t *testing.T) {
	workDir := t.TempDir()
	artifact := filepath.Join(workDir, "artifact.bin")
	checksums := filepath.Join(workDir, "checksums.txt")
	writeFile(t, artifact, "original")

	result := runScalp(t, workDir, "checksum", artifact)
	requireExitCode(t, result.exitCode, 0, result.String())
	writeFile(t, checksums, result.stdout)

	writeFile(t, artifact, "tampered")
	result = runScalp(t, workDir, "verify", "--artifact", artifact, "--checksum", checksums, "--ci")
	requireNonZero(t, result.exitCode, result.String())
	if !eventInAudit(readAuditLog(t, workDir), "event", "binary_verify") {
		t.Fatalf("expected binary_verify event in audit log")
	}
}
