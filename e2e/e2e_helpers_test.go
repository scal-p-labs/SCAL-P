//go:build e2e

package scalp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var binPath string

type scalpResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func (r *scalpResult) String() string {
	if r.stderr == "" {
		return r.stdout
	}
	return r.stdout + "\n" + r.stderr
}

func runScalp(t *testing.T, dir string, args ...string) *scalpResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run scalp: %v", err)
		}
	}
	return &scalpResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

func copyFixture(t *testing.T, fixturePath, destDir string) {
	t.Helper()
	err := filepath.WalkDir(fixturePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(fixturePath, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(destDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
}

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

func hasNodeModules(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "node_modules"))
	return err == nil && info.IsDir()
}

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

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available", name)
	}
}

func requireYarnBerry(t *testing.T) {
	t.Helper()
	requireCommand(t, "yarn")
	cmd := exec.Command("yarn", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Skip("yarn --version failed")
	}
	ver := strings.TrimSpace(out.String())
	parts := strings.SplitN(ver, ".", 2)
	if len(parts) == 0 {
		t.Skip("unknown yarn version")
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 2 {
		t.Skipf("yarn berry required, got %s", ver)
	}
}

var tsRegex = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)

func normalizeOutput(s string) string {
	s = tsRegex.ReplaceAllString(s, "0000-00-00T00:00:00Z")
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func readGolden(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func deleteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func removeDir(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func requireExitCode(t *testing.T, got, want int, output string) {
	t.Helper()
	if got != want {
		t.Fatalf("expected exit code %d, got %d\n%s", want, got, output)
	}
}

func requireNonZero(t *testing.T, code int, output string) {
	t.Helper()
	if code == 0 {
		t.Fatalf("expected non-zero exit code\n%s", output)
	}
}

func assertContains(t *testing.T, value, substr string) {
	t.Helper()
	if !strings.Contains(value, substr) {
		t.Fatalf("expected output to contain %q, got:\n%s", substr, value)
	}
}

func assertNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected %s to not exist", path)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func assertLockfileHasPackage(t *testing.T, lf map[string]any, name string) {
	t.Helper()
	pkgs, ok := lf["packages"].(map[string]any)
	if !ok {
		t.Fatal("lockfile should have packages field")
	}
	for key := range pkgs {
		if strings.Contains(key, name+"@") {
			return
		}
	}
	keys := make([]string, 0, len(pkgs))
	for k := range pkgs {
		keys = append(keys, k)
	}
	t.Fatalf("lockfile should contain %s entry, got: %v", name, keys)
}

func TestMain(m *testing.M) {
	buildDir, err := os.MkdirTemp("", "scalp-e2e")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	binPath = filepath.Join(buildDir, "scalp")
	cmd := exec.Command("go", "build", "-o", binPath, "../cmd/scalp")
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
