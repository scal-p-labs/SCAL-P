package pkgmanager

import (
	"context"
	"fmt"
	"log/slog"
)

// PackageNode is a flattened dependency node.
type PackageNode struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
	Path      string
	Depth     int
}

// DependencyTree models a package manager's dependency tree output.
type DependencyTree struct {
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Dependencies map[string]DependencyRef `json:"dependencies"`
}

// DependencyRef represents a dependency node in a package manager's tree.
type DependencyRef struct {
	Version      string                   `json:"version"`
	Resolved     string                   `json:"resolved"`
	Integrity    string                   `json:"integrity"`
	Path         string                   `json:"path"`
	Dependencies map[string]DependencyRef `json:"dependencies"`
}

// PackageManager abstracts operations over a specific package manager.
type PackageManager interface {
	// Name returns the package manager identifier (e.g., "npm", "pnpm").
	Name() string

	// Resolve resolves dependencies without installing (lockfile-only).
	Resolve(ctx context.Context, args ...string) error

	// GetTree returns the full dependency tree.
	GetTree(ctx context.Context) (DependencyTree, error)

	// Install runs the package manager's install command.
	Install(ctx context.Context, args ...string) error

	// ParseLockfile reads the PM-specific lockfile and returns a flat node list.
	ParseLockfile(ctx context.Context) ([]PackageNode, error)

	// LocalPath returns the local path for a package by name.
	LocalPath(name string) string
}

// maxFlattenNodes is the maximum number of packages Flatten will return.
// Real npm/pnpm projects can exceed 10K packages; this limit prevents
// unbounded memory growth from malicious or enormous dependency trees.
const maxFlattenNodes = 100000

// flattenEntry is a BFS queue entry for Flatten.
type flattenEntry struct {
	deps  map[string]DependencyRef
	depth int
}

// Flatten converts a dependency tree into a flat list of PackageNode.
// The same name@version may appear multiple times (hoisted duplicates).
// SyncWithTree handles this by overwriting lockfile entries.
//
// Returns an error if the tree exceeds maxFlattenNodes.
func Flatten(tree DependencyTree) ([]PackageNode, error) {
	if len(tree.Dependencies) == 0 {
		return nil, nil
	}

	var nodes []PackageNode
	queue := []flattenEntry{{deps: tree.Dependencies}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for name, ref := range cur.deps {
			if len(nodes) >= maxFlattenNodes {
				slog.Warn("Flatten: dependency tree truncated",
					"limit", maxFlattenNodes,
					"nodes", len(nodes),
				)
				return nodes, fmt.Errorf("dependency tree exceeds %d nodes", maxFlattenNodes)
			}

			nodes = append(nodes, PackageNode{
				Name:      name,
				Version:   ref.Version,
				Resolved:  ref.Resolved,
				Integrity: ref.Integrity,
				Path:      ref.Path,
				Depth:     cur.depth,
			})

			if len(ref.Dependencies) > 0 {
				queue = append(queue, flattenEntry{
					deps:  ref.Dependencies,
					depth: cur.depth + 1,
				})
			}
		}
	}

	return nodes, nil
}

// IsSupported reports whether the package manager name is known.
func IsSupported(pm string) bool {
	switch pm {
	case "npm", "pnpm":
		return true
	default:
		return false
	}
}

// IsScoped reports whether the package name is scoped.
func IsScoped(name string) bool {
	return len(name) > 0 && name[0] == '@'
}
