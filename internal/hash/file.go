package hash

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"scal-p/internal/ctxutil"
)

// File computes the SHA-512 hash of a single file using streaming.
// Returns "sha512-<base64>" — same format as Dir().
func File(ctx context.Context, path string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file %s: %w", path, err)
	}

	sum := h.Sum(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum), nil
}

// Bytes computes the SHA-512 hash of raw bytes.
// Returns "sha512-<base64>" — same format as File().
func Bytes(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}
