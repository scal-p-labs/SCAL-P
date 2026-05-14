package pkgmanager

import "context"

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

// Flatten converts a dependency tree into a flat list of PackageNode.
// The same name@version may appear multiple times (hoisted duplicates).
// SyncWithTree handles this by overwriting lockfile entries.
func Flatten(tree DependencyTree) []PackageNode {
	if len(tree.Dependencies) == 0 {
		return nil
	}
	var nodes []PackageNode
	visitDeps(tree.Dependencies, 0, &nodes, 0)
	return nodes
}

const maxFlattenDepth = 10000

func visitDeps(deps map[string]DependencyRef, depth int, nodes *[]PackageNode, guard int) {
	if guard > maxFlattenDepth {
		return
	}
	for name, ref := range deps {
		guard++
		*nodes = append(*nodes, PackageNode{
			Name:      name,
			Version:   ref.Version,
			Resolved:  ref.Resolved,
			Integrity: ref.Integrity,
			Path:      ref.Path,
			Depth:     depth,
		})
		if ref.Dependencies != nil {
			visitDeps(ref.Dependencies, depth+1, nodes, guard)
		}
	}
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
