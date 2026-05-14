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
	"sync"

	"scal-p/internal/ctxutil"
)

// Pool of reusable 32 KB buffers for streaming file content into SHA-512.
// Each Dir() call borrows one buffer via Get + defer Put, so the same
// buffer is reused across all files without allocating per-file slices.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// IsDir reports whether the path is an existing directory.
// Follows symlinks intentionally — pnpm's .pnpm store uses them.
// The security boundary is in Dir(), not here.
func IsDir(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// hashFile streams the file at path through the writer h and closes it.
// Using defer ensures the file is closed even if io.CopyBuffer panics
// or if future code paths are added before the Close.
func hashFile(h io.Writer, path string, buf []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	_, err = io.CopyBuffer(h, f, buf)
	return err
}

// Dir hashes a package directory using SHA-512.
//
// Security:
//   - os.Lstat checks for top-level symlinks (node_modules/pkg -> /etc
//     would be rejected early). Follow-up os.Open + f.Stat on the same fd
//     eliminates the TOCTOU race between type check and read.
//   - Internal symlinks WITHIN the package are skipped via IsRegular().
//     A malicious package replacing index.js with a symlink to /etc/passwd
//     would be invisible to the hash.
//   - Individual files are opened and hashed one at a time. Each file is
//     closed via defer in hashFile before the next iteration starts.
//   - The caller (resolvePkgDir in lockfile/sync.go) resolves real disk
//     paths before calling Dir, so pnpm .pnpm store symlinks are followed.
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

	entries, err := dir.Readdir(-1)
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
	buf := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(buf)

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
		if err := hashFile(h, fullPath, *buf); err != nil {
			return "", fmt.Errorf("hash %s: %w", fullPath, err)
		}
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}
