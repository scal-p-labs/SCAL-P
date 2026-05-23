package sanitize

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ShellMetacharacters contains characters that are dangerous in shell
// contexts. Even though Go's exec.CommandContext passes arguments as
// separate argv elements (no shell), validating these provides
// defense-in-depth.
const ShellMetacharacters = ";|`$&<>()[]{}!\\"

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

// ValidatePMArgs validates package manager arguments for shell
// metacharacters and control characters. Go's exec.CommandContext is
// inherently safe against shell injection (no shell), but this provides
// defense-in-depth against unexpected argument handling.
func ValidatePMArgs(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, ShellMetacharacters) {
			return fmt.Errorf("pmArg %q contains shell metacharacters", arg)
		}
		if strings.Contains(arg, "\n") || strings.Contains(arg, "\r") {
			return fmt.Errorf("pmArg %q contains control characters", arg)
		}
	}
	return nil
}

// HasTraversal checks if a filesystem path contains directory traversal
// components like ".." or ".". Uses filepath.ToSlash for cross-platform
// consistency. Also rejects absolute paths since they bypass relative
// path confinement.
func HasTraversal(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." || part == "." {
			return true
		}
	}
	return false
}
