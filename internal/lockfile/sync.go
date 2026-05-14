package lockfile

import (
	"context"
	"fmt"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/ctxutil"
	"scal-p/internal/hash"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
)

// SyncWithTree updates the lockfile based on the dependency tree.
func SyncWithTree(ctx context.Context, lf *Lockfile, tree pkgmanager.DependencyTree, pm pkgmanager.PackageManager) ([]audit.Event, error) {
	nodes := pkgmanager.Flatten(tree)
	events := make([]audit.Event, 0, len(nodes))
	now := time.Now().UTC().Format(time.RFC3339)

	for _, node := range nodes {
		if err := ctxutil.Check(ctx); err != nil {
			return nil, err
		}
		pkgDir := node.Path
		if pkgDir == "" {
			pkgDir = pm.LocalPath(node.Name)
		}
		if !hash.IsDir(pkgDir) {
			events = append(events, audit.Event{
				Timestamp: now,
				Event:     "hash_skipped",
				Package:   fmt.Sprintf("%s@%s", node.Name, node.Version),
				Status:    "warn",
				Reason:    "package_dir_not_found",
			})
			continue
		}

		integrity, err := hash.Dir(ctx, pkgDir)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", pkgDir, err)
		}

		key := fmt.Sprintf("%s@%s", node.Name, node.Version)
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
	nodes := pkgmanager.Flatten(tree)
	events := make([]audit.Event, 0, len(nodes))
	var violations []policy.Violation
	now := time.Now().UTC().Format(time.RFC3339)

	for _, node := range nodes {
		if err := ctxutil.Check(ctx); err != nil {
			return nil, nil, err
		}
		key := fmt.Sprintf("%s@%s", node.Name, node.Version)

		pkgDir := node.Path
		if pkgDir == "" {
			pkgDir = pm.LocalPath(node.Name)
		}

		entry, ok := lf.Packages[key]
		if !ok {
			if !hash.IsDir(pkgDir) {
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

		if !hash.IsDir(pkgDir) {
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

	return violations, events, nil
}

func statusFromMatch(match bool) string {
	if match {
		return "verified"
	}
	return "mismatch"
}
