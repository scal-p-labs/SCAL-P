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
// Each Dir() call borrows one buffer and returns it via defer, so the
// same buffer is reused across all files in a single hash run without
// allocating per-file buffers.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// IsDir reports whether the path is a directory. Follows symlinks
// intentionally — we want to resolve pnpm's .pnpm store symlinks.
// The security boundary is in Dir(), not here.
func IsDir(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Dir hashes a package directory using SHA-512.
//
// Security:
//   - os.Lstat checks for top-level symlinks (node_modules/pkg -> /etc
//     would be rejected early). Follow-up os.Open + f.Stat on the same fd
//     eliminates the TOCTOU race between check and read.
//   - Internal symlinks WITHIN the package are skipped via IsRegular().
//     A malicious package replacing index.js with a symlink to /etc/passwd
//     would be invisible to the hash.
//   - The caller (resolvePkgDir in lockfile/sync.go) resolves the real
//     disk path before passing it here, so pnpm's .pnpm store symlinks
//     are already followed.
func Dir(ctx context.Context, pkgPath string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	// Reject top-level symlinks before opening anything.
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

	// Same fd for Stat and Readdir — closes the TOCTOU window.
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

		// Only hash regular files. Symlinks, devices, sockets, etc.
		// inside a package are skipped — they're metadata, not content.
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

		f, err := os.Open(fullPath)
		if err != nil {
			return "", fmt.Errorf("open %s: %w", fullPath, err)
		}

		if _, err := io.CopyBuffer(h, f, *buf); err != nil {
			f.Close() //nolint:errcheck
			return "", fmt.Errorf("hash %s: %w", fullPath, err)
		}
		f.Close() //nolint:errcheck
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}
