package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
)

// PackageLock represents npm's package-lock.json format.
type PackageLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]LockPackage `json:"packages"`
}

// LockPackage is a package entry in package-lock.json.
type LockPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

// ParsePackageLock reads package-lock.json and returns a flat list of nodes.
func ParsePackageLock(ctx context.Context, path string) ([]pkgmanager.PackageNode, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("package-lock.json not found, run 'npm install --package-lock-only' first")
		}
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var pl PackageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	if pl.LockfileVersion < 2 {
		return nil, fmt.Errorf("unsupported lockfile version %d, need v2 or v3", pl.LockfileVersion)
	}

	var nodes []pkgmanager.PackageNode
	for pkgPath, pkg := range pl.Packages {
		if pkgPath == "" {
			continue
		}
		if !strings.HasPrefix(pkgPath, "node_modules/") {
			continue
		}

		name := extractName(pkgPath)
		if name == "" || isPathTraversal(name) {
			continue
		}
		depth := countNodeModules(pkgPath)

		nodes = append(nodes, pkgmanager.PackageNode{
			Name:      name,
			Version:   pkg.Version,
			Resolved:  pkg.Resolved,
			Integrity: pkg.Integrity,
			Path:      pkgPath,
			Depth:     depth,
		})
	}
	return nodes, nil
}

func (a *Adapter) resolveViaPackageLockOnly(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	cmdArgs := append([]string{"install", "--package-lock-only", "--ignore-scripts"}, args...)
	cmd := a.CommandContext(ctx, "npm", cmdArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install --package-lock-only failed: %w", err)
	}

	if _, err := os.Stat(filepath.Join(".", "package-lock.json")); err != nil {
		return fmt.Errorf("package-lock.json not created by resolution: %w", err)
	}
	return nil
}

func extractName(pkgPath string) string {
	idx := strings.LastIndex(pkgPath, "/node_modules/")
	trimmed := pkgPath[idx+len("/node_modules/"):]

	if strings.HasPrefix(trimmed, "@") {
		parts := strings.SplitN(trimmed, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return trimmed
	}
	parts := strings.Split(trimmed, "/")
	return parts[0]
}

// isPathTraversal checks if a package name could be a path traversal attack.
func isPathTraversal(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." {
			return true
		}
	}
	return false
}

func countNodeModules(pkgPath string) int {
	count := strings.Count(pkgPath, "node_modules")
	if count == 0 {
		return 0
	}
	return count - 1
}
