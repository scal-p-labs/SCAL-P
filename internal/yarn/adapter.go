package yarn

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

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
	pkgmanager.Register("yarn", func() pkgmanager.PackageManager {
		return New()
	})
}

func (a *Adapter) Name() string { return "yarn" }

func (a *Adapter) Resolve(ctx context.Context, args ...string) error {
	return a.resolveOnly(ctx, args...)
}

func (a *Adapter) resolveOnly(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	cmdArgs := append([]string{"install", "--mode=skip-build", "--immutable"}, args...)
	cmd := a.CommandContext(ctx, "yarn", cmdArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("yarn install --mode=skip-build --immutable failed: %w", err)
	}

	if _, err := os.Stat("yarn.lock"); err != nil {
		return fmt.Errorf("yarn.lock not found after resolution: %w", err)
	}
	return nil
}

type yarnInfoEntry struct {
	Value    string                    `json:"value"`
	Children map[string]yarnInfoEntry `json:"children"`
}

func (a *Adapter) GetTree(ctx context.Context) (pkgmanager.DependencyTree, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return pkgmanager.DependencyTree{}, err
	}

	nodes, err := ParseYarnLockfile(ctx)
	if err != nil {
		slog.Warn("lockfile parse failed, falling back to CLI", "err", err)
		return a.getTreeViaList(ctx)
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
		Name:         "yarn-project",
		Version:      "0.0",
		Dependencies: deps,
	}, nil
}

func (a *Adapter) getTreeViaList(ctx context.Context) (pkgmanager.DependencyTree, error) {
	cmd := a.CommandContext(ctx, "yarn", "info", "--all", "--recursive", "--json")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("yarn info start: %w", err)
	}

	allDeps := make(map[string]pkgmanager.DependencyRef)
	var rootName, rootVersion string

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry yarnInfoEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			slog.Warn("skipping unparseable yarn info line", "err", err)
			continue
		}

		if rootName == "" {
			rootName, rootVersion = splitYarnDescriptor(entry.Value)
		}
		for childKey, childEntry := range entry.Children {
			childName, childVer := splitYarnDescriptor(childEntry.Value)
			if childName == "" {
				childName, _ = splitYarnDescriptor(childKey)
			}
			allDeps[childName] = pkgmanager.DependencyRef{
				Version:      childVer,
				Dependencies: convertYarnInfoChildren(childEntry.Children),
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return pkgmanager.DependencyTree{}, fmt.Errorf("yarn info failed: %w", err)
		}
		slog.Warn("yarn info finished with non-zero exit — tree data may be incomplete",
			"exitCode", exitErr.ExitCode(),
		)
	}

	if rootName == "" {
		rootName = "yarn-project"
	}
	if rootVersion == "" {
		rootVersion = "0.0"
	}

	return pkgmanager.DependencyTree{
		Name:         rootName,
		Version:      rootVersion,
		Dependencies: allDeps,
	}, nil
}

func splitYarnDescriptor(value string) (name, version string) {
	idx := strings.LastIndex(value, "@npm:")
	if idx > 0 {
		return value[:idx], value[idx+len("@npm:"):]
	}
	idx = strings.LastIndex(value, "@")
	if idx > 0 {
		return value[:idx], value[idx+1:]
	}
	return value, ""
}

func convertYarnInfoChildren(children map[string]yarnInfoEntry) map[string]pkgmanager.DependencyRef {
	if len(children) == 0 {
		return nil
	}
	result := make(map[string]pkgmanager.DependencyRef, len(children))
	for childKey, childEntry := range children {
		childName, childVer := splitYarnDescriptor(childEntry.Value)
		if childName == "" {
			childName, _ = splitYarnDescriptor(childKey)
		}
		result[childName] = pkgmanager.DependencyRef{
			Version:      childVer,
			Dependencies: convertYarnInfoChildren(childEntry.Children),
		}
	}
	return result
}

func (a *Adapter) Install(ctx context.Context, args ...string) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}
	cmdArgs := append([]string{"install"}, args...)
	cmd := a.CommandContext(ctx, "yarn", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("yarn install failed: %w", err)
	}
	return nil
}

func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	return ParseYarnLockfile(ctx)
}

func (a *Adapter) LocalPath(name string) string {
	return "node_modules/" + name
}
