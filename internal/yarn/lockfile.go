package yarn

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/sanitize"
)

const (
	maxYarnLineLen = 10 * 1024
	maxYarnEntries = 100000
)

const (
	yarnIndentProp    = 2
	yarnIndentSubProp = 4
)

type yarnPkgEntry struct {
	name      string
	version   string
	integrity string
	resolved  string
}

type yarnParserState struct {
	current           *yarnPkgEntry
	inPackages        bool
	checksumPending   bool
	resolutionPending bool
	lineNum           int
}

var knownYarnProtocols = []string{
	"virtual:", "patch:", "npm:", "link:", "workspace:", "yarn:",
}

func ParseYarnLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	data, err := os.ReadFile("yarn.lock")
	if err != nil {
		return nil, fmt.Errorf("reading yarn.lock: %w", err)
	}

	return parseYarnLockYAML(data)
}

func parseYarnLockYAML(data []byte) ([]pkgmanager.PackageNode, error) {
	if len(data) == 0 {
		return nil, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, maxYarnLineLen), maxYarnLineLen)

	var entries []yarnPkgEntry
	state := &yarnParserState{}

	for scanner.Scan() {
		state.lineNum++

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			state.checksumPending = false
			state.resolutionPending = false
			continue
		}

		indent := yarnCountIndent(line)

		if !state.inPackages {
			if trimmed == "packages:" {
				return nil, fmt.Errorf("yarn.lock v1 (Classic) detected, only Berry (v2+) is supported")
			}
			if indent == 0 && strings.HasSuffix(trimmed, ":") {
				key := strings.TrimSuffix(trimmed, ":")
				key = strings.TrimSpace(key)
				if key == "__metadata" {
					continue
				}
				state.inPackages = true
				if err := state.startEntry(key); err != nil {
					return nil, err
				}
			}
			continue
		}

		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSuffix(trimmed, ":")
			key = strings.TrimSpace(key)
			if key == "__metadata" {
				state.flushEntry(&entries)
				state.inPackages = false
				continue
			}
			state.flushEntry(&entries)
			if err := state.startEntry(key); err != nil {
				return nil, err
			}
			state.checksumPending = false
			state.resolutionPending = false
			continue
		}

		if indent == 0 {
			state.inPackages = false
			continue
		}

		if err := yarnValidateIndent(indent); err != nil {
			return nil, err
		}

		switch {
		case indent == yarnIndentProp:
			if err := state.handleProperty(trimmed); err != nil {
				return nil, err
			}
		case indent >= yarnIndentSubProp:
			if err := state.handleSubProperty(trimmed); err != nil {
				return nil, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning yarn.lock: %w", err)
	}

	state.flushEntry(&entries)

	if len(entries) > maxYarnEntries {
		return nil, fmt.Errorf("too many packages (%d exceeds max %d)", len(entries), maxYarnEntries)
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

func (s *yarnParserState) startEntry(key string) error {
	key = strings.Trim(key, "\"")
	key = strings.TrimSpace(key)

	for _, proto := range knownYarnProtocols {
		atProto := "@" + proto
		idx := strings.LastIndex(key, atProto)
		if idx > 0 {
			name := key[:idx]
			descriptor := key[idx+1:]

			if strings.HasPrefix(descriptor, "virtual:") || strings.HasPrefix(descriptor, "patch:") {
				s.current = nil
				return nil
			}

			parts := strings.SplitN(descriptor, ":", 2)
			version := descriptor
			if len(parts) == 2 {
				version = parts[1]
			}

			version = strings.TrimSpace(version)
			version = strings.Trim(version, "\"'")
			version = strings.TrimRight(version, ", \t")

			if name == "" || version == "" {
				return fmt.Errorf("empty name or version in package key %q", key)
			}

			if err := sanitize.SanitizePackageName(name); err != nil {
				return fmt.Errorf("invalid package name in key %q: %w", key, err)
			}

			s.current = &yarnPkgEntry{
				name:    name,
				version: version,
			}
			return nil
		}
	}

	return fmt.Errorf("unrecognized package key format %q (expected Berry v2+ format)", key)
}

func (s *yarnParserState) handleProperty(trimmed string) error {
	if s.current == nil {
		return nil
	}

	switch {
	case strings.HasPrefix(trimmed, "version:"):
		val := yarnExtractColonValue(trimmed)
		if val != "" {
			s.current.version = val
		}

	case strings.HasPrefix(trimmed, "resolution:"):
		s.resolutionPending = false
		val := yarnExtractResolution(trimmed)
		if val != "" {
			s.current.resolved = val
		} else {
			s.resolutionPending = true
		}

	case strings.HasPrefix(trimmed, "checksum:"):
		s.checksumPending = false
		val := yarnExtractColonValue(trimmed)
		if val != "" {
			s.current.integrity = val
		} else {
			s.checksumPending = true
		}

	default:
		s.checksumPending = false
		s.resolutionPending = false
	}

	return nil
}

func (s *yarnParserState) handleSubProperty(trimmed string) error {
	if s.current == nil {
		return nil
	}

	trimmed = strings.TrimSpace(trimmed)

	switch {
	case s.resolutionPending && (strings.HasPrefix(trimmed, "tarball:") || strings.HasPrefix(trimmed, "url:")):
		val := yarnExtractColonValue(trimmed)
		if val != "" {
			s.current.resolved = val
		}
		s.resolutionPending = false

	case s.checksumPending:
		val := yarnExtractColonValue(trimmed)
		if val != "" {
			s.current.integrity = val
		}
		s.checksumPending = false
	}

	return nil
}

func (s *yarnParserState) flushEntry(entries *[]yarnPkgEntry) {
	if s.current != nil {
		*entries = append(*entries, *s.current)
		s.current = nil
	}
}

func yarnCountIndent(line string) int {
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

func yarnValidateIndent(indent int) error {
	if indent == yarnIndentProp || indent >= yarnIndentSubProp {
		return nil
	}
	return fmt.Errorf("unexpected indent level %d in yarn.lock", indent)
}

func yarnExtractColonValue(line string) string {
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

func yarnExtractResolution(line string) string {
	idx := strings.Index(line, "{")
	if idx != -1 {
		return yarnExtractInlineResolution(line[idx:])
	}

	val := yarnExtractColonValue(line)
	if val != "" {
		return val
	}

	return ""
}

func yarnExtractInlineResolution(line string) string {
	rest := strings.TrimPrefix(strings.TrimSpace(line), "resolution:")

	start := strings.Index(rest, "{")
	end := strings.Index(rest, "}")
	if start == -1 || end == -1 || end <= start {
		return yarnExtractColonValue(line)
	}

	inner := rest[start+1 : end]
	parts := strings.SplitN(inner, ":", 2)
	if len(parts) != 2 {
		return yarnExtractColonValue(line)
	}

	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, "\"'")
	val = strings.TrimRight(val, ", \t")

	return val
}
