package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzParsePackageLock(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"lockfileVersion":2,"packages":{}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-test=="}}}`,
		`{"lockfileVersion":2,"packages":{"node_modules/@scope/pkg":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":2,"packages":{"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0"}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		nodes, err := ParsePackageLock(context.Background(), path)
		if err != nil {
			return
		}
		for _, n := range nodes {
			if n.Name == "" {
				t.Errorf("empty name in parsed node")
			}
		}
	})
}
