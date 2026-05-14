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

// buffer pool for file hashing — reduces allocations vs allocating
// a new 32 KB buffer per file.
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
// Security decisions:
//   - os.Lstat is used FIRST to check for symlinks. If the path itself
//     is a symlink (e.g., node_modules/pkg -> /etc), we reject it
//     immediately. This prevents traversing outside the project tree.
//   - After the Lstat check, we open the directory with os.Open and use
//     the SAME file descriptor for both Stat and Readdir. This eliminates
//     the TOCTOU race between checking IsDir and reading entries.
//   - Internal symlinks WITHIN the package directory are skipped
//     (entry.Mode().IsRegular() rejects them). This prevents a malicious
//     package from replacing a file with a symlink to /etc/passwd.
//   - We do NOT follow pnpm's .pnpm store symlinks here — the
//     resolvePkgDir function in lockfile/sync.go resolves the real path
//     before calling Dir().
func Dir(ctx context.Context, pkgPath string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	// Reject top-level symlinks. The Lstat check catches node_modules/pkg
	// if it's a symlink to an arbitrary directory.
	fi, err := os.Lstat(pkgPath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", pkgPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to hash symlink: %s", pkgPath)
	}

	// Open the directory and use the SAME fd for both type check and
	// reading entries. This closes the TOCTOU window: an attacker
	// cannot swap the directory for a symlink between the IsDir check
	// and the ReadDir call.
	f, err := os.Open(pkgPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", pkgPath, err)
	}
	defer f.Close() //nolint:errcheck

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

	// Sort by name so the hash is deterministic regardless of
	// filesystem layout or OS readdir order.
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
	// Grab a buffer from the pool to reuse across files instead
	// of allocating a new 32 KB slice for every single file.
	buf := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(buf)

	for _, entry := range entries {
		if err := ctxutil.Check(ctx); err != nil {
			return "", err
		}
		// Only hash regular files. Skip symlinks, devices, etc.
		// Symlinks inside a package could point to sensitive files
		// — rejecting them here prevents that attack.
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

		// Stream file content through SHA-512 using a pooled buffer.
		// The pool avoids allocating a fresh 32 KB slice per file.
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
