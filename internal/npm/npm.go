package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
)

// ExecFunc matches the signature of exec.CommandContext.
type ExecFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd

// Adapter implements pkgmanager.PackageManager for npm.
type Adapter struct {
	// CommandContext creates external commands. Override in tests to mock.
	CommandContext ExecFunc
}

// New creates a new npm adapter with the default command factory.
func New() *Adapter {
	return &Adapter{CommandContext: exec.CommandContext}
}

// Register registers the npm adapter with the package manager registry.
func Register() {
	pkgmanager.Register("npm", func() pkgmanager.PackageManager {
		return New()
	})
}

func (a *Adapter) Name() string { return "npm" }

func (a *Adapter) Resolve(ctx context.Context, args ...string) error {
	return a.resolveViaPackageLockOnly(ctx, args...)
}

func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	return a.getDependencyTree(ctx)
}

func (a *Adapter) Install(ctx context.Context, args ...string) error {
	return a.runInstall(ctx, args)
}

// ParseLockfile reads package-lock.json and returns a flat node list.
func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	return ParsePackageLock(ctx, "package-lock.json")
}

// LocalPath returns the node_modules path for a package.
func (a *Adapter) LocalPath(name string) string {
	return "node_modules/" + name
}

func (a *Adapter) getDependencyTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}
	cmd := a.CommandContext(ctx, "npm", "ls", "--all", "--json")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("npm ls start: %w", err)
	}

	var tree pkgmanager.DependencyTree
	if err := json.NewDecoder(stdout).Decode(&tree); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("invalid dependency tree: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return pkgmanager.DependencyTree{}, fmt.Errorf("npm ls failed: %w", err)
		}
		slog.Warn("npm ls finished with non-zero exit — tree data may be incomplete",
			"exitCode", exitErr.ExitCode(),
		)
	}
	return tree, nil
}

func (a *Adapter) runInstall(ctx context.Context, args []string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := a.CommandContext(ctx, "npm", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install failed: %w", err)
	}
	return nil
}
