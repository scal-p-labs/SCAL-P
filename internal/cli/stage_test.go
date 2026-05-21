package cli

import (
	"bytes"
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

	// Create a test tarball
	tarball := []byte("fake-tarball-content")
	expectedHash := "sha512-wrong-hash"

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

	defer func() { os.Stdin = oldStdin }()

	err = runStageVerify(context.Background(), []string{
		"--stage-id", "test-pkg@1.0.0",
		"--policy", policyPath,
		"--checksum", expectedHash,
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

	tarball := []byte("valid-tarball-content")
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

	tarball := []byte("evil-tarball")

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

	sarifPath := filepath.Join(dir, "result.sarif")
	tarball := []byte("tarball-for-sarif")
	wrongHash := "sha512-this-is-definitely-wrong"

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

	defer func() { os.Stdin = oldStdin }()

	_ = runStageVerify(context.Background(), []string{
		"--stage-id", "sarif-pkg@1.0.0",
		"--policy", policyPath,
		"--checksum", wrongHash,
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
