package pnpm

import (
	"bufio"
	"bytes"
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

	// Fast path: parse pnpm-lock.yaml directly. This avoids the extremely
	// slow pnpm ls --depth Infinity (which can take minutes on large projects).
	nodes, err := ParsePnpmLockfile(ctx)
	if err != nil {
		// Fall back to pnpm ls --json --depth Infinity if lockfile parsing
		// fails (e.g., file not found, unsupported format).
		return a.getTreeViaLs(ctx)
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
		Name:         "pnpm-project",
		Version:      "0.0",
		Dependencies: deps,
	}, nil
}

func (a *Adapter) getTreeViaLs(ctx context.Context) (pkgmanager.DependencyTree, error) {
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
		slog.Warn("pnpm ls finished with non-zero exit — tree data may be incomplete",
			"exitCode", exitErr.ExitCode(),
		)
	}

	if len(entries) == 0 {
		return pkgmanager.DependencyTree{}, nil
	}

	root := entries[0]
	return pkgmanager.DependencyTree{
		Name:         root.Name,
		Version:      root.Version,
		Dependencies: convertPnpmDeps(root.Dependencies),
	}, nil
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

// Maximum line length for pnpm-lock.yaml parsing (safety limit).
const maxPnpmLineLen = 10 * 1024

// Maximum number of package entries (safety limit).
const maxPnpmEntries = 100000

// Known indent levels in pnpm-lock.yaml packages section.
const (
	indentPkgKey      = 2 // /lodash/4.17.21:
	indentPkgProperty = 4 // resolution:, engines:, dev:
	indentPkgSubProp  = 6 // integrity: sha512-... (under resolution:)
)

// lockfilePkgEntry holds parsed data for a single package in pnpm-lock.yaml.
type lockfilePkgEntry struct {
	name      string
	version   string
	integrity string
	resolved  string
}

// parserState tracks position within the lockfile during parsing.
type parserState struct {
	current           *lockfilePkgEntry
	inPackages        bool
	resolutionPending bool
	resolvedPending   bool
	lineNum           int
}

// parseLockfileYAML parses the packages section of a pnpm-lock.yaml file.
//
// Supported lockfile version range: v5.4 through v9+.
// This is NOT a full YAML parser. It only reads the "packages:" section
// and extracts name, version, integrity, and resolved URL for each entry.
//
// Known limitations:
//   - Peer dependencies are not parsed
//   - Optional dependencies are not distinguished
//   - Bundled dependencies are not parsed
//   - patchedDependencies and overrides are not supported
//   - Only /name/version and /name@version key formats
//   - dependencies/devDependencies inside package entries are not recursively parsed
//
// Security: The lockfile is treated as hostile input. The parser validates
// structure at every step and aborts with an error on unexpected input.
// Input size is bounded (max line length, max entry count).
func parseLockfileYAML(data []byte) ([]pkgmanager.PackageNode, error) {
	if len(data) == 0 {
		return nil, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, maxPnpmLineLen), maxPnpmLineLen)

	var entries []lockfilePkgEntry
	state := &parserState{}

	for scanner.Scan() {
		state.lineNum++

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			state.resolutionPending = false
			state.resolvedPending = false
			continue
		}

		indent := countIndent(line)

		if !state.inPackages {
			if trimmed == "packages:" {
				state.inPackages = true
			}
			continue
		}

		if indent == 0 {
			break
		}

		if err := validateIndent(indent); err != nil {
			return nil, err
		}

		switch {
		case indent == indentPkgKey && strings.HasSuffix(trimmed, ":"):
			state.flushEntry(&entries)

			key := strings.TrimSuffix(trimmed, ":")
			var err error
			state.current, err = parseLockfileKey(key)
			if err != nil {
				return nil, err
			}
			state.resolutionPending = false
			state.resolvedPending = false

		case indent == indentPkgProperty:
			if err := state.handleProperty(trimmed); err != nil {
				return nil, err
			}

		case indent == indentPkgSubProp:
			if err := state.handleSubProperty(trimmed); err != nil {
				return nil, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning pnpm-lock.yaml: %w", err)
	}

	state.flushEntry(&entries)

	if len(entries) > maxPnpmEntries {
		return nil, fmt.Errorf("too many packages (%d exceeds max %d)", len(entries), maxPnpmEntries)
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

// validateIndent returns an error if indent is not a known level.
func validateIndent(indent int) error {
	switch indent {
	case indentPkgKey, indentPkgProperty, indentPkgSubProp:
		return nil
	default:
		return fmt.Errorf("unexpected indent level %d (expected %d, %d, or %d)",
			indent, indentPkgKey, indentPkgProperty, indentPkgSubProp)
	}
}

// flushEntry appends the current entry to the entries slice and resets it.
func (s *parserState) flushEntry(entries *[]lockfilePkgEntry) {
	if s.current != nil {
		*entries = append(*entries, *s.current)
		s.current = nil
	}
}

// handleProperty processes an indent-4 line inside a package entry.
func (s *parserState) handleProperty(trimmed string) error {
	if s.current == nil {
		return fmt.Errorf("property %q outside a package entry", trimmed)
	}

	switch {
	case strings.HasPrefix(trimmed, "resolution:"):
		s.resolutionPending = false

		inline := extractInlineIntegrity(trimmed)
		if inline != "" {
			s.current.integrity = inline
		} else {
			s.resolutionPending = true
		}

	case strings.HasPrefix(trimmed, "resolved:"):
		s.resolvedPending = false

		val := extractColonValue(trimmed)
		if val != "" {
			s.current.resolved = val
		} else {
			s.resolvedPending = true
		}

	default:
		s.resolutionPending = false
		s.resolvedPending = false
	}

	return nil
}

// handleSubProperty processes an indent-6 line inside a multi-line block.
func (s *parserState) handleSubProperty(trimmed string) error {
	if s.current == nil {
		return fmt.Errorf("sub-property %q outside a package entry", trimmed)
	}

	switch {
	case s.resolutionPending && strings.HasPrefix(trimmed, "integrity:"):
		val := extractColonValue(trimmed)
		if val == "" {
			return fmt.Errorf("empty integrity value for package %s", s.current.name)
		}
		s.current.integrity = val
		s.resolutionPending = false

	case s.resolvedPending && strings.HasPrefix(trimmed, "integrity:"):
		val := extractColonValue(trimmed)
		if val == "" {
			return fmt.Errorf("empty integrity value for package %s", s.current.name)
		}
		s.current.integrity = val
		s.resolvedPending = false

	default:
		// Unknown sub-properties (e.g., "tarball:" inside resolution) are
		// silently skipped rather than rejected — they are valid YAML but
		// not relevant to SCAL-P's lockfile verification.
	}

	return nil
}

// countIndent counts leading whitespace characters in a line.
// Each space adds 1, each tab adds 2 (matching the 2-space indent convention).
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

// parseLockfileKey parses a package key from pnpm-lock.yaml into name and version.
//
// Key formats:
//   - /lodash/4.17.21         → name=lodash, version=4.17.21
//   - /@babel/code-frame/7.24.7 → name=@babel/code-frame, version=7.24.7
//   - /lodash@4.17.21         → name=lodash, version=4.17.21
//   - /@scope%2Fname/1.0.0    → name=@scope/name, version=1.0.0
func parseLockfileKey(key string) (*lockfilePkgEntry, error) {
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return nil, fmt.Errorf("empty package key")
	}

	splitAt := strings.LastIndex(key, "/")
	if splitAt == -1 {
		splitAt = strings.LastIndex(key, "@")
	}
	if splitAt == -1 || splitAt == 0 || splitAt == len(key)-1 {
		return nil, fmt.Errorf("malformed package key %q", key)
	}

	name := key[:splitAt]
	version := key[splitAt+1:]

	if name == "" || version == "" {
		return nil, fmt.Errorf("empty name or version in package key %q", key)
	}

	name = strings.ReplaceAll(name, "%2f", "/")
	name = strings.ReplaceAll(name, "%2F", "/")

	if strings.Contains(version, "/") {
		return nil, fmt.Errorf("version %q contains slash in package key %q", version, key)
	}

	return &lockfilePkgEntry{
		name:    name,
		version: version,
	}, nil
}

// extractInlineIntegrity extracts integrity from an inline resolution block.
// Handles both {integrity: sha512-...} and integrity: sha512-... on the same line.
func extractInlineIntegrity(line string) string {
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

	rest = strings.TrimRight(rest, ", \t")

	return rest
}

// extractColonValue extracts the value after the first colon in a line.
// Used for multi-line property values like "integrity: sha512-...".
func extractColonValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}

	val := line[idx+1:]
	val = strings.TrimSpace(val)
	val = strings.Trim(val, "\"'")
	val = strings.TrimRight(val, ", \t")

	return val
}

// LocalPath returns the node_modules path for a package.
// pnpm uses the same node_modules layout via symlinks.
func (a *Adapter) LocalPath(name string) string {
	return localPath(name)
}

func localPath(name string) string {
	return "node_modules/" + name
}
