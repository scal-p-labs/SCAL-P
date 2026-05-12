package hash

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
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
func Dir(ctx context.Context, pkgPath string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	entries, err := os.ReadDir(pkgPath)
	if err != nil {
		return "", fmt.Errorf("read dir %s: %w", pkgPath, err)
	}

	slices.SortFunc(entries, func(a, b os.DirEntry) int {
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
		if !entry.Type().IsRegular() {
			continue
		}
		fullPath := filepath.Join(pkgPath, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", fullPath, err)
		}
		if info.Size() == 0 {
			continue
		}

		if _, err := io.WriteString(h, entry.Name()+"\n"); err != nil {
			return "", fmt.Errorf("hash name %s: %w", fullPath, err)
		}

		f, err := os.Open(fullPath)
		if err != nil {
			return "", fmt.Errorf("open %s: %w", fullPath, err)
		}

		copyErr := func() (err error) {
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close %s: %w", fullPath, closeErr))
				}
			}()
			if _, err := io.Copy(h, f); err != nil {
				return fmt.Errorf("hash file %s: %w", fullPath, err)
			}
			return nil
		}()
		if copyErr != nil {
			return "", copyErr
		}
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}
