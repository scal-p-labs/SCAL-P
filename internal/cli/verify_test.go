package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/cli"
)

func TestVerifyDispatch(t *testing.T) {
	t.Run("ci dispatches as routed command", func(t *testing.T) {
		err := cli.Run([]string{"ci"})
		if err != nil && err.Error() == "unknown command: ci\n..." {
			t.Errorf("ci should be routed, not unknown: %v", err)
		}
	})

	t.Run("verify dispatches as routed command", func(t *testing.T) {
		err := cli.Run([]string{"verify", "--artifact", "x", "--checksum", "y"})
		if err != nil && strings.Contains(err.Error(), "unknown command") {
			t.Errorf("verify should be routed, got: %v", err)
		}
	})

	t.Run("checksum dispatches as routed command", func(t *testing.T) {
		err := cli.Run([]string{"checksum", "file"})
		if err != nil && strings.Contains(err.Error(), "unknown command") {
			t.Errorf("checksum should be routed, got: %v", err)
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("hash match passes", func(t *testing.T) {
		dir := t.TempDir()
		artifact := filepath.Join(dir, "release.tar.gz")
		checksums := filepath.Join(dir, "checksums.txt")

		if err := os.WriteFile(artifact, []byte("release binary content"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := cli.Run([]string{"checksum", "--output", checksums, artifact})
		if err != nil {
			t.Fatalf("checksum: %v", err)
		}

		err = cli.Run([]string{"verify", "--artifact", artifact, "--checksum", checksums})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("hash mismatch fails", func(t *testing.T) {
		dir := t.TempDir()
		artifact := filepath.Join(dir, "release.tar.gz")
		checksums := filepath.Join(dir, "checksums.txt")

		if err := os.WriteFile(artifact, []byte("original content"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := cli.Run([]string{"checksum", "--output", checksums, artifact})
		if err != nil {
			t.Fatalf("checksum: %v", err)
		}

		if err := os.WriteFile(artifact, []byte("tampered content"), 0o644); err != nil {
			t.Fatal(err)
		}

		err = cli.Run([]string{"verify", "--artifact", artifact, "--checksum", checksums, "--ci"})
		if err == nil {
			t.Fatal("expected error for hash mismatch")
		}
		if !strings.Contains(err.Error(), "hash_mismatch") {
			t.Errorf("expected hash_mismatch error, got %v", err)
		}
	})

	t.Run("--artifact is required", func(t *testing.T) {
		err := cli.Run([]string{"verify", "--checksum", "some-file"})
		if err == nil {
			t.Fatal("expected error without --artifact")
		}
	})

	t.Run("--checksum is required", func(t *testing.T) {
		err := cli.Run([]string{"verify", "--artifact", "some-file"})
		if err == nil {
			t.Fatal("expected error without --checksum")
		}
	})

	t.Run("artifact not in checksums file", func(t *testing.T) {
		dir := t.TempDir()
		artifact := filepath.Join(dir, "unknown.tar.gz")
		checksums := filepath.Join(dir, "checksums.txt")

		if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}

		otherFile := filepath.Join(dir, "other.tar.gz")
		if err := os.WriteFile(otherFile, []byte("other"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := cli.Run([]string{"checksum", "--output", checksums, otherFile})
		if err != nil {
			t.Fatalf("checksum: %v", err)
		}

		err = cli.Run([]string{"verify", "--artifact", artifact, "--checksum", checksums})
		if err == nil {
			t.Fatal("expected error for artifact not in checksums")
		}
	})
}
