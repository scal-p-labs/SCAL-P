package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/hash"
	"scal-p/internal/policy"
)

func TestRunStage_NoArgs(t *testing.T) {
	err := runStage(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "stage requires a subcommand") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStage_UnknownSubcommand(t *testing.T) {
	err := runStage(context.Background(), []string{"unknown"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown stage subcommand") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStageVerify_RequiresStageID(t *testing.T) {
	err := runStageVerify(context.Background(), []string{})
	if err == nil {
		t.Fatal("expected error for missing --stage-id")
	}
	if !strings.Contains(err.Error(), "--stage-id is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStageVerify_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	tarball := buildTestTarball(t, "test-pkg")

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "test-pkg@1.0.0",
		"--policy", policyPath,
		"--checksum", "sha512-wrong-hash",
		"--ci",
	})
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if !strings.Contains(err.Error(), "hash_mismatch") {
		t.Errorf("expected hash_mismatch in error, got: %v", err)
	}
}

func TestRunStageVerify_HashMatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	tarball := buildTestTarball(t, "test-pkg")
	expectedHash := hash.Bytes(tarball)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "test-pkg@1.0.0",
		"--policy", policyPath,
		"--checksum", expectedHash,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestRunStageVerify_Denylist(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[{"name":"evil-pkg"}]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	tarball := buildTestTarball(t, "evil-pkg")

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "evil-pkg@2.0.0",
		"--policy", policyPath,
		"--ci",
	})
	if err == nil {
		t.Fatal("expected error for denylist match")
	}
	if !strings.Contains(err.Error(), "denylist") {
		t.Errorf("expected denylist in error, got: %v", err)
	}
}

func TestRunStageVerify_SarifOutput(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	sarifPath := filepath.Join(dir, "result.sarif")
	tarball := buildTestTarball(t, "sarif-pkg")

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	_ = runStageVerify(context.Background(), []string{
		"--stage-id", "sarif-pkg@1.0.0",
		"--policy", policyPath,
		"--checksum", "sha512-this-is-definitely-wrong",
		"--sarif", sarifPath,
	})

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("expected sarif file at %s: %v", sarifPath, err)
	}
	if !bytes.Contains(data, []byte("stage_verify")) {
		t.Errorf("expected stage_verify rule in sarif, got: %s", string(data))
	}
	if !bytes.Contains(data, []byte("hash_mismatch")) {
		t.Errorf("expected hash_mismatch in sarif, got: %s", string(data))
	}
}

func TestDenylistCheck(t *testing.T) {
	pol := policy.Policy{
		Packages: policy.Packages{
			Deny: []policy.PackageRule{
				{Name: "malicious"},
				{Name: "evil-pkg"},
			},
		},
	}

	if !denylistCheck(pol, "malicious@1.0.0") {
		t.Error("expected malicious@1.0.0 to be denied")
	}
	if denylistCheck(pol, "safe-pkg@1.0.0") {
		t.Error("expected safe-pkg@1.0.0 to be allowed")
	}
}

func TestStageVerify_UsageInHelp(t *testing.T) {
	usage := usageText()
	if !strings.Contains(usage, "stage verify") {
		t.Error("expected 'stage verify' in usage text")
	}
}

func TestExtractPkgNameFromTarball(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		tarball := buildTestTarball(t, "my-package")
		name, err := extractPkgNameFromTarball(bytes.NewReader(tarball))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "my-package" {
			t.Errorf("expected my-package, got %s", name)
		}
	})

	t.Run("not found", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		hdr := &tar.Header{
			Name: "package/README.md",
			Size: 0,
			Mode: 0o644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}

		name, err := extractPkgNameFromTarball(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "" {
			t.Errorf("expected empty name, got %s", name)
		}
	})

	t.Run("invalid gzip", func(t *testing.T) {
		_, err := extractPkgNameFromTarball(bytes.NewReader([]byte("not-gzip")))
		if err == nil {
			t.Fatal("expected error for invalid gzip data")
		}
	})
}

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		pattern string
		pkgName string
		match   bool
	}{
		{"*", "anything", true},
		{"@scope/*", "@scope/pkg", true},
		{"@scope/*", "@other/pkg", false},
		{"*substr*", "prefix-substr-suffix", true},
		{"*substr*", "no-match", false},
		{"*suffix", "prefix-suffix", true},
		{"*suffix", "prefix-other", false},
		{"prefix*", "prefix-suffix", true},
		{"prefix*", "other-suffix", false},
		{"exact", "exact", true},
		{"exact", "Exact", true},
		{"Exact", "exact", true},
		{"@Scope/*", "@scope/pkg", true},
		{"evil-pkg", "Evil-Pkg", true},
	}

	for _, tc := range tests {
		got := patternMatch(tc.pattern, tc.pkgName)
		if got != tc.match {
			t.Errorf("patternMatch(%q, %q) = %v, want %v", tc.pattern, tc.pkgName, got, tc.match)
		}
	}
}

func TestStagePkgName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"lodash@4.17.21", "lodash"},
		{"@scope/pkg@1.0.0", "@scope/pkg"},
		{"is-number@7.0.0", "is-number"},
		{"no-version", "no-version"},
	}

	for _, tc := range tests {
		got := stagePkgName(tc.input)
		if got != tc.expected {
			t.Errorf("stagePkgName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestExtractPkgName_StageIDMismatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	tarball := buildTestTarball(t, "real-pkg")

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "fake-pkg@1.0.0",
		"--policy", policyPath,
		"--ci",
	})
	if err == nil {
		t.Fatal("expected error for stage ID mismatch")
	}
	if !strings.Contains(err.Error(), "stage_id_mismatch") {
		t.Errorf("expected stage_id_mismatch in error, got: %v", err)
	}
}

func TestExtractPkgName_DenylistAgainstTarball(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"trust":{"mode":"audit-only"},"packages":{"allow":[],"deny":[{"name":"evil"}]},"enforcement":{"on_violation":"warn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	tarball := buildTestTarball(t, "evil")

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		_, _ = w.Write(tarball)
		_ = w.Close()
	}()
	defer func() { _ = r.Close() }()
	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "not-evil@1.0.0",
		"--policy", policyPath,
		"--ci",
	})
	if err == nil {
		t.Fatal("expected error for denylist match against tarball content")
	}
	if !strings.Contains(err.Error(), "denylist") {
		t.Errorf("expected denylist in error, got: %v", err)
	}
}

func buildTestTarball(t *testing.T, pkgName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte(`{"name":"` + pkgName + `","version":"1.0.0"}`)
	hdr := &tar.Header{
		Name: "package/package.json",
		Size: int64(len(content)),
		Mode: 0o644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
