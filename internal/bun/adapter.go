package bun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/sanitize"
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
		return fmt.Errorf("bun install --frozen-lockfile failed: %w", err)
	}

	if hasLockfile() {
		return nil
	}

	return fmt.Errorf("bun.lock not found after resolution")
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

func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}

	// Use bun pm ls --all to get the dependency tree. This preserves proper
	// parent-child nesting and handles multiple versions of the same package,
	// unlike the lockfile parser which returns a flat name-keyed map that
	// cannot represent duplicate package names at different versions.
	return a.getTreeViaPm(ctx)
}

func countTreeDepth(line string) int {
	depth := 0
	for _, r := range line {
		if r == '│' {
			depth++
		}
		if r == '├' || r == '└' {
			break
		}
	}
	// If the line starts with ├ or └ directly, depth is already 0
	return depth
}

type flatPmEntry struct {
	name    string
	version string
	depth   int
	parent  int
}

func parsePmLsTree(output string) (rootName string, deps map[string]bunPmEntry) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", nil
	}

	rootLine := strings.TrimSpace(lines[0])
	rootName = "bun-project"
	if fields := strings.Fields(rootLine); len(fields) > 0 {
		rootName = filepath.Base(fields[0])
	}

	var flat []flatPmEntry
	for _, line := range lines[1:] {
		depth := countTreeDepth(line)

		cleaned := strings.TrimLeft(line, " ├└│─")
		cleaned = strings.TrimSpace(cleaned)
		if cleaned == "" {
			continue
		}

		name, version := bunSplitNameVersion(cleaned)
		if name == "" || version == "" {
			continue
		}
		if err := sanitize.SanitizePackageName(name); err != nil {
			slog.Warn("skipping package with invalid name from CLI",
				"name", name, "err", err)
			continue
		}

		parent := -1
		for i := len(flat) - 1; i >= 0; i-- {
			if flat[i].depth == depth-1 {
				parent = i
				break
			}
		}

		flat = append(flat, flatPmEntry{
			name:    name,
			version: version,
			depth:   depth,
			parent:  parent,
		})
	}

	if len(flat) == 0 {
		return rootName, nil
	}

	nodes := make([]bunPmEntry, len(flat))
	for i, f := range flat {
		nodes[i] = bunPmEntry{
			Name:         f.name,
			Version:      f.version,
			Dependencies: make(map[string]bunPmEntry),
		}
	}

	deps = make(map[string]bunPmEntry, len(flat))
	for i := len(flat) - 1; i >= 0; i-- {
		f := flat[i]
		if f.parent == -1 {
			deps[f.name] = nodes[i]
		} else {
			p := &nodes[f.parent]
			p.Dependencies[f.name] = nodes[i]
		}
	}

	return rootName, deps
}

func (a *Adapter) getTreeViaPm(ctx context.Context) (pkgmanager.DependencyTree, error) {
	cmd := a.CommandContext(ctx, "bun", "pm", "ls", "--all")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("bun pm ls start: %w", err)
	}

	output, err := io.ReadAll(stdout)
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("reading bun pm ls output: %w", err)
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

	rootName, deps := parsePmLsTree(string(output))
	if rootName == "" {
		return pkgmanager.DependencyTree{}, nil
	}

	return pkgmanager.DependencyTree{
		Name:         rootName,
		Version:      "0.0",
		Dependencies: convertBunDeps(deps),
	}, nil
}

func convertBunDeps(deps map[string]bunPmEntry) map[string]pkgmanager.DependencyRef {
	if len(deps) == 0 {
		return nil
	}
	result := make(map[string]pkgmanager.DependencyRef, len(deps))
	for name, entry := range deps {
		if err := sanitize.SanitizePackageName(name); err != nil {
			slog.Warn("skipping package with invalid name from CLI",
				"name", name, "err", err)
			continue
		}
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
