package bun

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

type ExecFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd

type Adapter struct {
	CommandContext ExecFunc
}

func New() *Adapter {
	return &Adapter{CommandContext: exec.CommandContext}
}

func Register() {
	pkgmanager.Register("bun", func() pkgmanager.PackageManager {
		return New()
	})
}

func (a *Adapter) Name() string { return "bun" }

func (a *Adapter) Resolve(ctx context.Context, args ...string) error {
	return a.resolveOnly(ctx, args...)
}

func (a *Adapter) resolveOnly(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	cmdArgs := append([]string{"install", "--frozen-lockfile"}, args...)
	cmd := a.CommandContext(ctx, "bun", cmdArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return a.installFallback(ctx, args...)
	}

	if hasLockfile() {
		return nil
	}

	return a.installFallback(ctx, args...)
}

func (a *Adapter) installFallback(ctx context.Context, args ...string) error {
	cmdArgs := append([]string{"install"}, args...)
	cmd := a.CommandContext(ctx, "bun", cmdArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bun install failed: %w", err)
	}
	return nil
}

func hasLockfile() bool {
	_, err := os.Stat("bun.lock")
	if err == nil {
		return true
	}
	_, err = os.Stat("bun.lockb")
	return err == nil
}

type bunPmEntry struct {
	Name         string                `json:"name"`
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Integrity    string                `json:"integrity"`
	Dependencies map[string]bunPmEntry `json:"dependencies"`
}

type bunPmOutput []bunPmEntry

func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}

	nodes, err := ParseBunLockfile(ctx)
	if err != nil {
		return a.getTreeViaPm(ctx)
	}

	deps := make(map[string]pkgmanager.DependencyRef, len(nodes))
	for _, node := range nodes {
		deps[node.Name] = pkgmanager.DependencyRef{
			Version:   node.Version,
			Resolved:  node.Resolved,
			Integrity: node.Integrity,
			Path:      "node_modules/" + node.Name,
		}
	}
	return pkgmanager.DependencyTree{
		Name:         "bun-project",
		Version:      "0.0",
		Dependencies: deps,
	}, nil
}

func (a *Adapter) getTreeViaPm(ctx context.Context) (pkgmanager.DependencyTree, error) {
	cmd := a.CommandContext(ctx, "bun", "pm", "ls", "--all", "--json")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("bun pm ls start: %w", err)
	}

	var output bunPmOutput
	if err := json.NewDecoder(stdout).Decode(&output); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("invalid bun pm ls output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return pkgmanager.DependencyTree{}, fmt.Errorf("bun pm ls failed: %w", err)
		}
		slog.Warn("bun pm ls finished with non-zero exit — tree data may be incomplete",
			"exitCode", exitErr.ExitCode(),
		)
	}

	if len(output) == 0 {
		return pkgmanager.DependencyTree{}, nil
	}

	root := output[0]
	return pkgmanager.DependencyTree{
		Name:         root.Name,
		Version:      root.Version,
		Dependencies: convertBunDeps(root.Dependencies),
	}, nil
}

func convertBunDeps(deps map[string]bunPmEntry) map[string]pkgmanager.DependencyRef {
	if len(deps) == 0 {
		return nil
	}
	result := make(map[string]pkgmanager.DependencyRef, len(deps))
	for name, entry := range deps {
		result[name] = pkgmanager.DependencyRef{
			Version:      entry.Version,
			Resolved:     entry.Resolved,
			Path:         "node_modules/" + name,
			Dependencies: convertBunDeps(entry.Dependencies),
		}
	}
	return result
}

func (a *Adapter) Install(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := a.CommandContext(ctx, "bun", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bun install failed: %w", err)
	}
	return nil
}

func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	return ParseBunLockfile(ctx)
}

func (a *Adapter) LocalPath(name string) string {
	return "node_modules/" + name
}
