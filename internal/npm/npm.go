package npm

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

// Adapter implements pkgmanager.PackageManager for npm.
type Adapter struct{}

// Register registers the npm adapter with the package manager registry.
func Register() {
	pkgmanager.Register("npm", func() pkgmanager.PackageManager {
		return &Adapter{}
	})
}

// Name returns the package manager identifier.
func (a *Adapter) Name() string { return "npm" }

// Resolve runs npm install --package-lock-only to resolve dependencies.
func (a *Adapter) Resolve(ctx context.Context, args ...string) error {
	return ResolveViaPackageLockOnly(ctx, args...)
}

// GetTree returns the npm dependency tree.
func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	return GetDependencyTree(ctx)
}

// Install runs npm install with passthrough arguments.
func (a *Adapter) Install(ctx context.Context, args ...string) error {
	return RunInstall(ctx, args)
}

// ParseLockfile reads package-lock.json and returns a flat node list.
func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	return ParsePackageLock(ctx, "package-lock.json")
}

// LocalPath returns the node_modules path for a package.
func (a *Adapter) LocalPath(name string) string {
	return LocalPath(name)
}

// GetDependencyTree returns npm's dependency tree.
func GetDependencyTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}
	cmd := execCommand(ctx, "npm", "ls", "--all", "--json")
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("failed to run npm ls: %w", err)
	}

	var tree pkgmanager.DependencyTree
	if err := json.Unmarshal(output, &tree); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("invalid dependency tree: %w", err)
	}
	return tree, nil
}

// RunInstall runs npm install with passthrough arguments.
func RunInstall(ctx context.Context, args []string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := execCommand(ctx, "npm", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install failed: %w", err)
	}
	return nil
}

// LocalPath returns the node_modules path for a package.
func LocalPath(name string) string {
	return "node_modules/" + name
}
