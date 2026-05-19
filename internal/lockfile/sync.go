package lockfile

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/ctxutil"
	"scal-p/internal/hash"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
)

// SyncWithTree updates the lockfile based on the dependency tree.
func SyncWithTree(ctx context.Context, lf *Lockfile, tree pkgmanager.DependencyTree, pm pkgmanager.PackageManager) ([]audit.Event, error) {
	nodes, err := pkgmanager.Flatten(tree)
	if err != nil {
		return nil, fmt.Errorf("flatten tree: %w", err)
	}
	events := make([]audit.Event, 0, len(nodes))
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}

	for _, node := range nodes {
		key := fmt.Sprintf("%s@%s", node.Name, node.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		if err := ctxutil.Check(ctx); err != nil {
			return nil, err
		}
		pkgDir := resolvePkgDir(node, pm)
		if pkgDir == "" {
			events = append(events, audit.Event{
				Timestamp: now,
				Event:     "hash_skipped",
				Package:   key,
				Status:    "warn",
				Reason:    "package_dir_not_found",
			})
			continue
		}

		integrity, err := hash.Dir(ctx, pkgDir)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", pkgDir, err)
		}

		lf.Packages[key] = LockEntry{
			Resolved:   node.Resolved,
			Integrity:  integrity,
			VerifiedAt: now,
		}
		events = append(events, audit.Event{
			Timestamp: now,
			Event:     "hash_verified",
			Package:   key,
			Status:    "verified",
			HashMatch: true,
		})
	}

	return events, nil
}

// VerifyAgainstTree checks the lockfile against the dependency tree.
func VerifyAgainstTree(ctx context.Context, lf *Lockfile, tree pkgmanager.DependencyTree, pm pkgmanager.PackageManager) ([]policy.Violation, []audit.Event, error) {
	nodes, err := pkgmanager.Flatten(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("flatten tree: %w", err)
	}
	events := make([]audit.Event, 0, len(nodes))
	var violations []policy.Violation
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}

	for _, node := range nodes {
		key := fmt.Sprintf("%s@%s", node.Name, node.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := ctxutil.Check(ctx); err != nil {
			return nil, nil, err
		}
		pkgDir := resolvePkgDir(node, pm)

		entry, ok := lf.Packages[key]
		if !ok {
			if pkgDir == "" {
				continue
			}
			violations = append(violations, policy.Violation{
				PackageID: key,
				Reason:    "missing_lock_entry",
				Rule:      "lockfile",
			})
			events = append(events, audit.Event{
				Timestamp: now,
				Event:     "hash_missing",
				Package:   key,
				Status:    "warn",
				Reason:    "missing_lock_entry",
			})
			continue
		}

		if pkgDir == "" {
			violations = append(violations, policy.Violation{
				PackageID: key,
				Reason:    "package_not_installed",
				Rule:      "lockfile",
			})
			events = append(events, audit.Event{
				Timestamp: now,
				Event:     "hash_check",
				Package:   key,
				Status:    "missing",
				Reason:    "package_not_installed",
			})
			continue
		}

		integrity, err := hash.Dir(ctx, pkgDir)
		if err != nil {
			return nil, nil, fmt.Errorf("hash %s: %w", pkgDir, err)
		}

		match := entry.Integrity == integrity
		if !match {
			violations = append(violations, policy.Violation{
				PackageID: key,
				Reason:    "hash_mismatch",
				Rule:      "lockfile",
			})
		}

		events = append(events, audit.Event{
			Timestamp: now,
			Event:     "hash_check",
			Package:   key,
			Status:    statusFromMatch(match),
			HashMatch: match,
		})
	}

	missingKeys := make([]string, 0, len(lf.Packages))
	for key := range lf.Packages {
		if !seen[key] {
			missingKeys = append(missingKeys, key)
		}
	}
	sort.Strings(missingKeys)
	for _, key := range missingKeys {
		if err := ctxutil.Check(ctx); err != nil {
			return nil, nil, err
		}
		violations = append(violations, policy.Violation{
			PackageID: key,
			Reason:    "package_not_installed",
			Rule:      "lockfile",
		})
		events = append(events, audit.Event{
			Timestamp: now,
			Event:     "hash_check",
			Package:   key,
			Status:    "missing",
			Reason:    "package_not_installed",
		})
	}

	return violations, events, nil
}

// resolvePkgDir tries the path reported by the package manager first,
// then falls back to node_modules/<name>. For pnpm, the reported path is
// a symlink (node_modules/pkg -> .pnpm/pkg@v/node_modules/pkg), so we
// resolve it to the real path before returning — hash.Dir rejects symlinks.
func resolvePkgDir(node pkgmanager.PackageNode, pm pkgmanager.PackageManager) string {
	path := node.Path
	if path == "" || !hash.IsDir(path) {
		path = pm.LocalPath(node.Name)
		if !hash.IsDir(path) {
			return ""
		}
		if node.Path != "" && node.Path != path {
			slog.Debug("package resolved via fallback",
				"pkg", node.Name, "reported", node.Path, "found", path)
		}
	}
	// Resolve pnpm symlinks so hash.Dir (which rejects symlinks via os.Lstat)
	// receives the real directory path instead of a symlink.
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		slog.Debug("resolve symlink", "path", path, "err", err)
		return path
	}
	return realPath
}

func statusFromMatch(match bool) string {
	if match {
		return "verified"
	}
	return "mismatch"
}
