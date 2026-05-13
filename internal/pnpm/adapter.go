package pnpm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
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

// Adapter implements pkgmanager.PackageManager for pnpm.
type Adapter struct{}

// Register registers the pnpm adapter with the package manager registry.
func Register() {
	pkgmanager.Register("pnpm", func() pkgmanager.PackageManager {
		return &Adapter{}
	})
}

// Name returns the package manager identifier.
func (a *Adapter) Name() string { return "pnpm" }

// Resolve runs pnpm install --lockfile-only to resolve dependencies.
func (a *Adapter) Resolve(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	cmdArgs := append([]string{"install", "--lockfile-only"}, args...)
	cmd := execCommand(ctx, "pnpm", cmdArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pnpm install --lockfile-only failed: %w", err)
	}

	if _, err := os.Stat("pnpm-lock.yaml"); err != nil {
		return fmt.Errorf("pnpm-lock.yaml not created by resolution: %w", err)
	}
	return nil
}

// pnpmListEntry represents a single entry in pnpm ls --json output.
type pnpmListEntry struct {
	Name         string                       `json:"name"`
	Version      string                       `json:"version"`
	Path         string                       `json:"path"`
	Dependencies map[string]pnpmDependencyRef `json:"dependencies"`
}

// pnpmDependencyRef represents a dependency in pnpm's list output.
type pnpmDependencyRef struct {
	From         string                       `json:"from"`
	Version      string                       `json:"version"`
	Resolved     string                       `json:"resolved"`
	Path         string                       `json:"path"`
	Dependencies map[string]pnpmDependencyRef `json:"dependencies"`
}

// GetTree returns pnpm's dependency tree by running pnpm ls --json --depth Infinity.
func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}

	cmd := execCommand(ctx, "pnpm", "ls", "--json", "--depth", "Infinity")
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("failed to run pnpm ls: %w", err)
	}

	// pnpm ls --json returns an array with a single project entry.
	var entries []pnpmListEntry
	if err := json.Unmarshal(output, &entries); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("invalid pnpm ls output: %w", err)
	}

	if len(entries) == 0 {
		return pkgmanager.DependencyTree{}, nil
	}

	root := entries[0]
	tree := pkgmanager.DependencyTree{
		Name:         root.Name,
		Version:      root.Version,
		Dependencies: convertPnpmDeps(root.Dependencies),
	}
	return tree, nil
}

// convertPnpmDeps converts pnpm's dependency format to pkgmanager.DependencyRef.
func convertPnpmDeps(deps map[string]pnpmDependencyRef) map[string]pkgmanager.DependencyRef {
	if len(deps) == 0 {
		return nil
	}
	result := make(map[string]pkgmanager.DependencyRef, len(deps))
	for name, ref := range deps {
		result[name] = pkgmanager.DependencyRef{
			Version:      ref.Version,
			Resolved:     ref.Resolved,
			Path:         ref.Path,
			Dependencies: convertPnpmDeps(ref.Dependencies),
		}
	}
	return result
}

// Install runs pnpm install with passthrough arguments.
func (a *Adapter) Install(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := execCommand(ctx, "pnpm", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pnpm install failed: %w", err)
	}
	return nil
}

func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	tree, err := a.GetTree(ctx)
	if err != nil {
		return nil, err
	}
	return pkgmanager.Flatten(tree), nil
}

// LocalPath returns the node_modules path for a package.
// pnpm uses the same node_modules layout via symlinks.
func (a *Adapter) LocalPath(name string) string {
	return localPath(name)
}

func localPath(name string) string {
	return "node_modules/" + name
}
