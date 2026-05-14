package pnpm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("pnpm ls start: %w", err)
	}

	var entries []pnpmListEntry
	if err := json.NewDecoder(stdout).Decode(&entries); err != nil {
		return pkgmanager.DependencyTree{}, fmt.Errorf("invalid pnpm ls output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return pkgmanager.DependencyTree{}, fmt.Errorf("pnpm ls failed: %w", err)
		}
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

// ParseLockfile reads pnpm-lock.yaml and returns a flat list of PackageNode.
// Unlike GetTree, this works without node_modules being installed.
func (a *Adapter) ParseLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	return ParsePnpmLockfile(ctx)
}

// ParsePnpmLockfile reads pnpm-lock.yaml and returns a flat list of PackageNode.
func ParsePnpmLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	data, err := os.ReadFile("pnpm-lock.yaml")
	if err != nil {
		return nil, fmt.Errorf("reading pnpm-lock.yaml: %w", err)
	}

	return parseLockfileYAML(data)
}

// lockfilePkgEntry holds parsed data for a single package in pnpm-lock.yaml.
type lockfilePkgEntry struct {
	name      string
	version   string
	integrity string
	resolved  string
}

func parseLockfileYAML(data []byte) ([]pkgmanager.PackageNode, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var entries []lockfilePkgEntry
	var current *lockfilePkgEntry
	inPackages := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !inPackages {
			if trimmed == "packages:" {
				inPackages = true
			}
			continue
		}

		indent := countIndent(line)

		if indent == 0 && trimmed != "" {
			break
		}

		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				entries = append(entries, *current)
			}

			key := strings.TrimSuffix(trimmed, ":")
			current = parseLockfileKey(key)
			continue
		}

		if current != nil && indent == 4 {
			if strings.HasPrefix(trimmed, "resolution:") {
				current.integrity = extractIntegrity(trimmed)
			}
		}
	}

	if current != nil {
		entries = append(entries, *current)
	}

	nodes := make([]pkgmanager.PackageNode, 0, len(entries))
	for _, e := range entries {
		nodes = append(nodes, pkgmanager.PackageNode{
			Name:      e.name,
			Version:   e.version,
			Resolved:  e.resolved,
			Integrity: e.integrity,
			Path:      "node_modules/" + e.name,
			Depth:     0,
		})
	}

	return nodes, nil
}

func countIndent(line string) int {
	n := 0
	for _, c := range line {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 2
		default:
			return n
		}
	}
	return n
}

func parseLockfileKey(key string) *lockfilePkgEntry {
	key = strings.TrimPrefix(key, "/")

	lastSlash := strings.LastIndex(key, "/")
	if lastSlash == -1 {
		return nil
	}
	name := key[:lastSlash]
	version := key[lastSlash+1:]

	name = strings.ReplaceAll(name, "%2f", "/")
	name = strings.ReplaceAll(name, "%2F", "/")

	return &lockfilePkgEntry{
		name:    name,
		version: version,
	}
}

func extractIntegrity(line string) string {
	idx := strings.Index(line, "{integrity:")
	if idx == -1 {
		idx = strings.Index(line, "integrity: ")
		if idx == -1 {
			idx = strings.Index(line, "integrity:")
			if idx == -1 {
				return ""
			}
		}
	}

	rest := line[idx:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx == -1 {
		return ""
	}

	rest = rest[colonIdx+1:]
	rest = strings.TrimSpace(rest)

	end := strings.Index(rest, "}")
	if end != -1 {
		rest = rest[:end]
	}

	rest = strings.TrimSpace(rest)
	rest = strings.Trim(rest, "\"'")

	// Handle trailing , or whitespace
	rest = strings.TrimRight(rest, ", \t")

	return rest
}

// LocalPath returns the node_modules path for a package.
// pnpm uses the same node_modules layout via symlinks.
func (a *Adapter) LocalPath(name string) string {
	return localPath(name)
}

func localPath(name string) string {
	return "node_modules/" + name
}
