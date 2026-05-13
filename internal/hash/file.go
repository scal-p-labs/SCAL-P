package hash

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"

	"scal-p/internal/ctxutil"
)

// File computes the SHA-512 hash of a single file.
// Returns "sha512-<base64>" — same format as Dir().
func File(ctx context.Context, path string) (string, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return "", err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file %s: %w", path, err)
	}

	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
