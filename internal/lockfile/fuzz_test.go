package lockfile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func FuzzLockfileLoad(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"lockVersion":2,"packages":{}}`,
		`{"lockVersion":2,"generatedAt":"2025-01-01T00:00:00Z","packages":{"lodash@4.17.21":{"resolved":"https://...","integrity":"sha512-test==","verifiedAt":"2025-01-01T00:00:00Z"}}}`,
		`{"lockVersion":2,"packages":{"@scope/pkg@1.0.0":{"resolved":"https://...","integrity":"sha512-test==","verifiedAt":"2025-01-01T00:00:00Z"}}}`,
		`{"lockVersion":2,"packages":{},"signing_key":"invalid!","signature":"bad=="}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lockfile.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		lf, err := Load(context.Background(), path)
		if err != nil {
			return
		}
		if lf.LockVersion == 0 {
			t.Errorf("lock version should be defaulted to 2")
		}
	})
}

func FuzzVerifySignature(f *testing.F) {
	validKey := "MCowBQYDK2VwAyEAqkzM7Xp8vG6z7F5Q6H4f3d2s1a9b8c7d6e5f4g3h2i1j0k=="

	seeds := []string{
		`{"lockVersion":2,"packages":{}}`,
		`{"lockVersion":2,"packages":{"lodash@4.17.21":{"resolved":"https://...","integrity":"sha512-test==","verifiedAt":"2025-01-01T00:00:00Z"}}}`,
		`{"lockVersion":2,"packages":{},"signing_key":"` + validKey + `","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var lf Lockfile
		if err := json.Unmarshal(data, &lf); err != nil {
			return
		}
		_ = VerifySignature(&lf)
	})
}
