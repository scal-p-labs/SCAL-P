package lockfile

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"scal-p/internal/ctxutil"
	"scal-p/internal/ioutil"
)

// Lockfile contains hashes for installed packages.
type Lockfile struct {
	LockVersion int                  `json:"lockVersion"`
	GeneratedAt string               `json:"generatedAt"`
	Packages    map[string]LockEntry `json:"packages"`
}

// LockEntry represents a locked package entry.
type LockEntry struct {
	Resolved   string `json:"resolved"`
	Integrity  string `json:"integrity"`
	VerifiedAt string `json:"verifiedAt"`
}

// Load reads the lockfile from disk or returns a default empty lockfile.
func Load(ctx context.Context, path string) (Lockfile, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return Lockfile{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Lockfile{LockVersion: 1, Packages: map[string]LockEntry{}}, nil
		}
		return Lockfile{}, fmt.Errorf("read lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return Lockfile{}, fmt.Errorf("decode lockfile: %w", err)
	}
	if lf.Packages == nil {
		lf.Packages = map[string]LockEntry{}
	}
	lf.LockVersion = cmp.Or(lf.LockVersion, 1)
	return lf, nil
}

// Save writes the lockfile to disk atomically.
func Save(ctx context.Context, path string, lf Lockfile) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lockfile: %w", err)
	}
	return ioutil.WriteFileAtomic(path, data, 0o644)
}
