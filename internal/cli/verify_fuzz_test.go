package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseChecksums(f *testing.F) {
	seeds := []string{
		"",
		"# comment",
		"sha512-abc123  file.txt",
		"sha512-abc123  file.txt\nsha512-def456  other.bin",
		"malformed-line-no-delimiter",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "checksums.txt")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := parseChecksums(path)
		if err != nil {
			return
		}
	})
}
