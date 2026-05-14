package hash

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"scal-p/internal/ctxutil"
)

// IsDir reports whether the path is a directory.
func IsDir(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Dir hashes a package directory using SHA-512.
// Rejects symlinks to prevent traversal outside the project tree.
// Uses a single file descriptor for both type check and read (TOCTOU-safe).
func Dir(ctx context.Context, pkgPath string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	fi, err := os.Lstat(pkgPath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", pkgPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to hash symlink: %s", pkgPath)
	}

	f, err := os.Open(pkgPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", pkgPath, err)
	}
	defer f.Close()

	fi2, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", pkgPath, err)
	}
	if !fi2.IsDir() {
		return "", fmt.Errorf("not a directory: %s", pkgPath)
	}

	entries, err := f.Readdir(-1)
	if err != nil {
		return "", fmt.Errorf("read dir %s: %w", pkgPath, err)
	}

	slices.SortFunc(entries, func(a, b os.FileInfo) int {
		if a.Name() < b.Name() {
			return -1
		}
		if a.Name() > b.Name() {
			return 1
		}
		return 0
	})

	h := sha512.New()
	for _, entry := range entries {
		if err := ctxutil.Check(ctx); err != nil {
			return "", err
		}
		if !entry.Mode().IsRegular() {
			continue
		}
		fullPath := filepath.Join(pkgPath, entry.Name())
		if entry.Size() == 0 {
			continue
		}

		if _, err := io.WriteString(h, entry.Name()+"\n"); err != nil {
			return "", fmt.Errorf("hash name %s: %w", fullPath, err)
		}

		data, err := os.ReadFile(fullPath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fullPath, err)
		}
		if _, err := h.Write(data); err != nil {
			return "", fmt.Errorf("hash %s: %w", fullPath, err)
		}
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}
