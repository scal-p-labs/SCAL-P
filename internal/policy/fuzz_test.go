package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzPolicyLoad(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"version":1,"trust":{"mode":"allowlist","min_score":50},"packages":{"allow":[{"name":"lodash"}],"deny":[{"name":"malicious"}]},"enforcement":{"on_violation":"block"}}`,
		`{"trust":{"mode":"denylist"},"packages":{"deny":[{"pattern":"*evil*"}]}}`,
		`{"enforcement":{"on_violation":"warn","default_mode":"passthrough"}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		pol, info, err := Load(context.Background(), path)
		if err != nil {
			return
		}
		if info.MissingPolicy {
			t.Errorf("unexpected missing policy for existing file")
		}
		if pol.Version == 0 {
			t.Errorf("version should be defaulted to 1")
		}
	})
}
