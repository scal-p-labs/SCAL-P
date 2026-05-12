package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"scal-p/internal/ctxutil"
)

// execCommand is the function used to create external commands.
// Override in tests to mock command execution.
var execCommand = exec.CommandContext

// ExecFunc matches the signature of exec.CommandContext.
type ExecFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd

// SetExecCommand overrides the command factory for testing.
// Returns the previous function for restore.
func SetExecCommand(fn ExecFunc) ExecFunc {
	old := execCommand
	execCommand = fn
	return old
}

// DependencyTree models the npm ls --json output.
type DependencyTree struct {
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Dependencies map[string]DependencyRef `json:"dependencies"`
}

// DependencyRef represents a dependency node in npm's tree.
type DependencyRef struct {
	Version      string                   `json:"version"`
	Resolved     string                   `json:"resolved"`
	Integrity    string                   `json:"integrity"`
	Path         string                   `json:"path"`
	Dependencies map[string]DependencyRef `json:"dependencies"`
}

// PackageNode is a flattened dependency node.
type PackageNode struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
	Path      string
	Depth     int
}

// IsSupported reports whether the package manager is supported.
func IsSupported(pm string) bool {
	switch pm {
	case "npm", "pnpm", "yarn":
		return true
	default:
		return false
	}
}

// GetDependencyTree returns npm's dependency tree.
func GetDependencyTree(ctx context.Context, pm string) (DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return DependencyTree{}, err
	}
	if !IsSupported(pm) {
		return DependencyTree{}, fmt.Errorf("unsupported package manager: %s", pm)
	}
	if pm != "npm" {
		return DependencyTree{}, fmt.Errorf("dependency tree not supported for %s in v0.1", pm)
	}
	cmd := execCommand(ctx, pm, "ls", "--all", "--json")
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return DependencyTree{}, fmt.Errorf("failed to run %s ls: %w", pm, err)
	}

	var tree DependencyTree
	if err := json.Unmarshal(output, &tree); err != nil {
		return DependencyTree{}, fmt.Errorf("invalid dependency tree: %w", err)
	}
	return tree, nil
}

// RunInstall runs npm install with passthrough arguments.
func RunInstall(ctx context.Context, pm string, args []string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	if !IsSupported(pm) {
		return fmt.Errorf("unsupported package manager: %s", pm)
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := execCommand(ctx, pm, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s install failed: %w", pm, err)
	}
	return nil
}

// Flatten converts a dependency tree into a flat list of PackageNode.
func Flatten(tree DependencyTree) []PackageNode {
	if tree.Dependencies == nil {
		return nil
	}
	var nodes []PackageNode
	visitDeps(tree.Dependencies, 0, &nodes)
	return nodes
}

func visitDeps(deps map[string]DependencyRef, depth int, nodes *[]PackageNode) {
	for name, ref := range deps {
		*nodes = append(*nodes, PackageNode{
			Name:      name,
			Version:   ref.Version,
			Resolved:  ref.Resolved,
			Integrity: ref.Integrity,
			Path:      ref.Path,
			Depth:     depth,
		})
		if ref.Dependencies != nil {
			visitDeps(ref.Dependencies, depth+1, nodes)
		}
	}
}

// ResolveNode finds a dependency by name in a dependency map.
func ResolveNode(deps map[string]DependencyRef, name string) (DependencyRef, error) {
	if deps == nil {
		return DependencyRef{}, errors.New("dependencies empty")
	}
	if ref, ok := deps[name]; ok {
		return ref, nil
	}
	return DependencyRef{}, fmt.Errorf("package not found: %s", name)
}

// LocalPath returns the node_modules path for a package.
func LocalPath(name string) string {
	return "node_modules/" + name
}

// IsScoped reports whether the package name is scoped.
func IsScoped(name string) bool {
	return len(name) > 0 && name[0] == '@'
}
