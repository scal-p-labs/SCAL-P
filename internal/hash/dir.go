package hash

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"scal-p/internal/ctxutil"
)

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func IsDir(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func hashFile(h io.Writer, path string, buf []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	_, err = io.CopyBuffer(h, f, buf)
	return err
}

func collectFiles(ctx context.Context, pkgPath string) ([]string, error) {
	var entries []string
	err := filepath.WalkDir(pkgPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(pkgPath, path)
		if err != nil {
			return fmt.Errorf("relative path %s: %w", path, err)
		}
		entries = append(entries, rel)
		return nil
	})
	return entries, err
}

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

	dir, err := os.Open(pkgPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", pkgPath, err)
	}
	defer dir.Close() //nolint:errcheck

	fi, err = dir.Stat()
	if err != nil {
		return "", fmt.Errorf("stat dir %s: %w", pkgPath, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("not a directory: %s", pkgPath)
	}

	entries, err := collectFiles(ctx, pkgPath)
	if err != nil {
		return "", fmt.Errorf("walk %s: %w", pkgPath, err)
	}

	slices.Sort(entries)

	h := sha512.New()
	buf := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(buf)

	for _, rel := range entries {
		if err := ctxutil.Check(ctx); err != nil {
			return "", err
		}

		fullPath := filepath.Join(pkgPath, rel)

		if _, err := io.WriteString(h, rel+"\n"); err != nil {
			return "", fmt.Errorf("hash name %s: %w", fullPath, err)
		}
		if err := hashFile(h, fullPath, *buf); err != nil {
			return "", fmt.Errorf("hash %s: %w", fullPath, err)
		}
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}
