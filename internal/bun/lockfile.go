package bun

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"scal-p/internal/ctxutil"
	"scal-p/internal/pkgmanager"
)

const (
	maxBunLineLen = 10 * 1024
	maxBunEntries = 100000
)

const (
	bunIndentProp = 2
)

type bunPkgEntry struct {
	name      string
	version   string
	integrity string
	resolved  string
}

type bunParserState struct {
	current *bunPkgEntry
	lineNum int
	inDeps  bool
}

func ParseBunLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	data, err := os.ReadFile("bun.lock")
	if err != nil {
		return nil, fmt.Errorf("reading bun.lock: %w", err)
	}

	return parseBunLockText(data)
}

func parseBunLockText(data []byte) ([]pkgmanager.PackageNode, error) {
	if len(data) == 0 {
		return nil, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, maxBunLineLen), maxBunLineLen)

	var entries []bunPkgEntry
	state := &bunParserState{}

	for scanner.Scan() {
		state.lineNum++

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			state.inDeps = false
			continue
		}

		indent := bunCountIndent(line)

		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			state.flushEntry(&entries)
			key := strings.TrimSuffix(trimmed, ":")
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if err := state.startEntry(key); err != nil {
				return nil, err
			}
			state.inDeps = false
			continue
		}

		if indent == 0 {
			state.flushEntry(&entries)
			continue
		}

		if err := bunValidateIndent(indent); err != nil {
			return nil, err
		}

		if state.current == nil {
			continue
		}

		if indent == bunIndentProp {
			if err := state.handleProperty(trimmed); err != nil {
				return nil, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning bun.lock: %w", err)
	}

	state.flushEntry(&entries)

	if len(entries) > maxBunEntries {
		return nil, fmt.Errorf("too many packages (%d exceeds max %d)", len(entries), maxBunEntries)
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

func (s *bunParserState) startEntry(key string) error {
	key = strings.Trim(key, "\"")
	key = strings.TrimSpace(key)

	if key == "" {
		return nil
	}

	idx := strings.LastIndex(key, "@")
	if idx <= 0 {
		// scoped package without version (@scope/pkg) or bare key
		s.current = &bunPkgEntry{name: key}
		return nil
	}

	name := key[:idx]
	version := key[idx+1:]

	if name == "" {
		s.current = &bunPkgEntry{name: key}
		return nil
	}

	// scoped package: leading @ is valid, but @ at any other position or a comma means malformed
	if strings.Contains(name[1:], "@") || strings.ContainsAny(name, ",") {
		return fmt.Errorf("malformed package key %q", key)
	}

	s.current = &bunPkgEntry{
		name:    name,
		version: version,
	}
	return nil
}

func (s *bunParserState) handleProperty(trimmed string) error {
	if s.current == nil {
		return nil
	}

	s.inDeps = false

	switch {
	case strings.HasPrefix(trimmed, "version:"):
		val := bunExtractColonValue(trimmed)
		if val != "" {
			s.current.version = val
		}

	case strings.HasPrefix(trimmed, "resolution:"):
		val := bunExtractColonValue(trimmed)
		if val != "" {
			s.current.resolved = val
		}

	case strings.HasPrefix(trimmed, "integrity:"):
		val := bunExtractColonValue(trimmed)
		if val != "" {
			s.current.integrity = val
		}

	case strings.HasPrefix(trimmed, "dependencies:"):
		s.inDeps = true

	case strings.HasPrefix(trimmed, "optionalDependencies:"):
		s.inDeps = true

	default:
		s.inDeps = false
	}

	return nil
}

func (s *bunParserState) flushEntry(entries *[]bunPkgEntry) {
	if s.current != nil {
		*entries = append(*entries, *s.current)
		s.current = nil
	}
	s.inDeps = false
}

func bunCountIndent(line string) int {
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

func bunValidateIndent(indent int) error {
	if indent >= bunIndentProp {
		return nil
	}
	return fmt.Errorf("unexpected indent level %d in bun.lock", indent)
}

func bunExtractColonValue(line string) string {
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
