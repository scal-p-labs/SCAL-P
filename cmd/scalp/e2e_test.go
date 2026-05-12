//go:build e2e

package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

// scalp runs the binary with the given args and returns the result.
func scalp(t *testing.T, dir string, args ...string) *scalpResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	var exitCode int
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run scalp: %v", err)
		}
	}
	return &scalpResult{stdout: string(out), exitCode: exitCode}
}

type scalpResult struct {
	stdout   string
	exitCode int
}

func (r *scalpResult) String() string { return r.stdout }

// initNpmProject creates a fresh npm project in the given directory.
func initNpmProject(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("npm", "init", "-y")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("npm init failed: %v\n%s", err, out)
	}
}

// writePolicy writes a policy JSON file.
func writePolicy(t *testing.T, dir string, content string) {
	t.Helper()
	pdir := filepath.Join(dir, ".scalp")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "policy.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readAuditLog returns all events from the audit log.
func readAuditLog(t *testing.T, dir string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".scalp", "audit.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil
	}
	var events []map[string]any
	for _, line := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("invalid audit log line: %v\n%s", err, line)
		}
		events = append(events, ev)
	}
	return events
}

// readLockfile returns the lockfile content.
func readLockfile(t *testing.T, dir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".scalp", "lockfile.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var lf map[string]any
	if err := json.Unmarshal(data, &lf); err != nil {
		t.Fatalf("invalid lockfile: %v", err)
	}
	return lf
}

// hasNodeModules reports whether node_modules exists.
func hasNodeModules(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "node_modules"))
	return err == nil && info.IsDir()
}

func keysOf(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// eventInAudit checks if an event with matching field exists in the audit log.
func eventInAudit(events []map[string]any, key, value string) bool {
	for _, ev := range events {
		if v, ok := ev[key]; ok {
			if s, ok := v.(string); ok && s == value {
				return true
			}
		}
	}
	return false
}

// Block before install
// ____________________

func TestE2E_BlockBeforeInstall(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)
	writePolicy(t, dir, `{
		"version":1,
		"trust":{"mode":"denylist"},
		"packages":{"deny":[{"name":"is-odd"}]},
		"enforcement":{"on_violation":"block","default_mode":"guarded"}
	}`)

	result := scalp(t, dir, "install", "--pm", "npm", "is-odd")

	if result.exitCode == 0 {
		t.Error("expected non-zero exit code, got 0")
	}
	if hasNodeModules(dir) {
		t.Error("node_modules should NOT exist (blocked before install)")
	}

	events := readAuditLog(t, dir)
	if !eventInAudit(events, "event", "policy_violation") {
		t.Errorf("audit.log should contain policy_violation, got: %+v", events)
	}
}

// Happy path
// ----------

func TestE2E_HappyPath(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)

	result := scalp(t, dir, "install", "--pm", "npm", "lodash")

	if result.exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d: %s", result.exitCode, result)
	}
	if !hasNodeModules(dir) {
		t.Fatal("node_modules should exist after install")
	}

	lf := readLockfile(t, dir)
	if lf == nil {
		t.Fatal("lockfile should exist after install")
	}

	pkgs, ok := lf["packages"].(map[string]any)
	if !ok {
		t.Fatal("lockfile should have packages field")
	}
	var found bool
	for key := range pkgs {
		if strings.Contains(key, "lodash@") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lockfile should contain lodash entry, got: %v", keysOf(pkgs))
	}
}

// Tampering detection
// ___________________

func TestE2E_TamperingDetection(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)

	result := scalp(t, dir, "install", "--pm", "npm", "lodash")
	if result.exitCode != 0 {
		t.Fatalf("install failed: %s", result)
	}

	lodashDir := filepath.Join(dir, "node_modules", "lodash")
	entries, err := os.ReadDir(lodashDir)
	if err != nil {
		t.Fatal(err)
	}
	tampered := false
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

	result = scalp(t, dir, "audit", "--pm", "npm", "--ci")

	if result.exitCode == 0 {
		t.Error("expected non-zero exit code after tampering, got 0")
	}

	events := readAuditLog(t, dir)
	if !eventInAudit(events, "status", "mismatch") {
		t.Errorf("expected hash mismatch in audit log, got: %+v", events)
	}
}

// Package audit detects stale/missing packages
// ---------------------------------------------

func TestE2E_MissingPackage(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)

	result := scalp(t, dir, "install", "--pm", "npm", "lodash")
	if result.exitCode != 0 {
		t.Fatalf("install failed: %s", result)
	}

	// Simulating corruption: the goal is to delete the package-lock.json file and reinstall lodash
	// then the original entry in the lock file will become obsolete
	// afterwards, partially delete the node_modules/lodash folder so that the verification fails
	pkgDir := filepath.Join(dir, "node_modules", "lodash")

	if err := os.WriteFile(filepath.Join(pkgDir, "injected.js"), []byte("/* malware */"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Audit with --ci should detect hash mismatch
	result = scalp(t, dir, "audit", "--pm", "npm", "--ci")

	if result.exitCode == 0 {
		t.Error("expected non-zero exit code for modified package, got 0")
	}

	events := readAuditLog(t, dir)
	if !eventInAudit(events, "status", "mismatch") {
		t.Errorf("expected hash mismatch in audit log, got: %+v", events)
	}
}

// Unauthorized dependency (allowlist blocks)
// ------------------------------------------

func TestE2E_UnauthorizedDependency(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)
	writePolicy(t, dir, `{
		"version":1,
		"trust":{"mode":"allowlist"},
		"packages":{"allow":[{"name":"lodash"}]},
		"enforcement":{"on_violation":"block","default_mode":"guarded"}
	}`)

	result := scalp(t, dir, "install", "--pm", "npm", "lodash", "is-odd")

	if result.exitCode == 0 {
		t.Error("expected non-zero exit code (blocked), got 0")
	}
	if hasNodeModules(dir) {
		t.Error("node_modules should NOT exist (blocked pre-install)")
	}

	events := readAuditLog(t, dir)
	if !eventInAudit(events, "event", "policy_violation") {
		t.Errorf("expected policy_violation in audit log, got: %+v", events)
	}
}

// Audit-only mode
// ---------------

func TestE2E_AuditOnly(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)
	writePolicy(t, dir, `{
		"version":1,
		"trust":{"mode":"audit-only"},
		"packages":{"deny":[{"name":"is-odd"}]},
		"enforcement":{"on_violation":"warn","default_mode":"guarded"}
	}`)

	result := scalp(t, dir, "install", "--pm", "npm", "is-odd")

	if result.exitCode != 0 {
		t.Errorf("expected exit code 0 in audit-only, got %d", result.exitCode)
	}
	if !hasNodeModules(dir) {
		t.Error("node_modules should exist in audit-only mode")
	}
}

// Reproducibility — lockfile stable across repeated installs
// ---------------------------------------------------------

func TestE2E_Reproducibility(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)

	if r := scalp(t, dir, "install", "--pm", "npm", "lodash"); r.exitCode != 0 {
		t.Fatalf("first install failed: %s", r)
	}
	lf1 := readLockfile(t, dir)
	if lf1 == nil {
		t.Fatal("lockfile not created after first install")
	}

	if r := scalp(t, dir, "install", "--pm", "npm"); r.exitCode != 0 {
		t.Fatalf("second install failed: %s", r)
	}
	lf2 := readLockfile(t, dir)
	if lf2 == nil {
		t.Fatal("lockfile not found after second install")
	}

	pkgs1, _ := lf1["packages"].(map[string]any)
	pkgs2, _ := lf2["packages"].(map[string]any)

	for key, entry1 := range pkgs1 {
		entry2, ok := pkgs2[key]
		if !ok {
			t.Errorf("package %s disappeared from lockfile", key)
			continue
		}
		e1, _ := entry1.(map[string]any)
		e2, _ := entry2.(map[string]any)
		if e1["integrity"] != e2["integrity"] {
			t.Errorf("integrity changed for %s after reinstall", key)
		}
	}
}

// -----------------------------

func TestE2E_CIFlag(t *testing.T) {
	dir := t.TempDir()
	initNpmProject(t, dir)
	writePolicy(t, dir, `{
		"version":1,
		"trust":{"mode":"denylist"},
		"packages":{"deny":[{"name":"is-odd"}]},
		"enforcement":{"on_violation":"block","default_mode":"guarded"}
	}`)

	result := scalp(t, dir, "install", "--pm", "npm", "--ci", "is-odd")
	if result.exitCode == 0 {
		t.Error("expected non-zero exit code with --ci, got 0")
	}
}

func TestMain(m *testing.M) {
	buildDir, err := os.MkdirTemp("", "scalp-e2e")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	binPath = filepath.Join(buildDir, "scalp")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.RemoveAll(buildDir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(buildDir)
	os.Exit(code)
}
