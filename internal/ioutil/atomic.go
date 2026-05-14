package ioutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultPerm is used when WriteFileAtomic is called without a perm argument.
const defaultPerm os.FileMode = 0o644

// WriteFileAtomic writes data to path atomically: writes to a .tmp file
// first, then renames it over the target. On failure the temp file is
// cleaned up and the target file is left untouched.
//
// The perm argument is optional (variadic for backward compat). When
// omitted, 0644 is used.
func WriteFileAtomic(path string, data []byte, perm ...os.FileMode) error {
	mode := defaultPerm
	if len(perm) > 0 {
		mode = perm[0]
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
