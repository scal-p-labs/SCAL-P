package sanitize

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SanitizePackageName validates a package name for safe filesystem use.
// Package names come from lockfiles or CLI output and may contain path
// traversal sequences like ".." or ".".
func SanitizePackageName(name string) error {
	if name == "" {
		return errors.New("package name is empty")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" {
			return fmt.Errorf("package name %q contains empty path component", name)
		}
		if part == ".." || part == "." {
			return fmt.Errorf("package name %q contains path traversal component", name)
		}
	}
	return nil
}

// HasTraversal checks if a filesystem path contains directory traversal
// components like ".." or ".". Uses filepath.ToSlash for cross-platform
// consistency.
func HasTraversal(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." || part == "." {
			return true
		}
	}
	return false
}
