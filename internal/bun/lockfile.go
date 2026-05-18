package bun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

func bunSplitNameVersion(s string) (name, version string) {
	if strings.HasPrefix(s, "@") {
		rest := s[1:]
		if idx := strings.LastIndex(rest, "@"); idx > 0 {
			return "@" + rest[:idx], rest[idx+1:]
		}
		return s, ""
	}
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

type bunLockJSONPackage [4]json.RawMessage

type bunLockJSON struct {
	LockfileVersion int                            `json:"lockfileVersion"`
	Packages        map[string]bunLockJSONPackage  `json:"packages"`
}

func sanitizeBunJSON(data []byte) []byte {
	var out bytes.Buffer
	inString := false
	escape := false

	for i := 0; i < len(data); i++ {
		b := data[i]

		if escape {
			escape = false
			out.WriteByte(b)
			continue
		}

		if b == '\\' && inString {
			escape = true
			out.WriteByte(b)
			continue
		}

		if b == '"' {
			inString = !inString
			out.WriteByte(b)
			continue
		}

		if !inString && b == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}

		out.WriteByte(b)
	}

	return out.Bytes()
}

func parseBunLockJSON(data []byte) ([]pkgmanager.PackageNode, error) {
	cleaned := sanitizeBunJSON(data)

	var hdr bunLockJSON
	if err := json.Unmarshal(cleaned, &hdr); err != nil {
		return nil, fmt.Errorf("parsing JSON bun.lock: %w", err)
	}

	nodes := make([]pkgmanager.PackageNode, 0, len(hdr.Packages))
	for _, entry := range hdr.Packages {
		if len(entry) < 1 {
			continue
		}

		var nameVersion string
		if err := json.Unmarshal(entry[0], &nameVersion); err != nil {
			continue
		}

		pkgName, version := bunSplitNameVersion(nameVersion)
		if pkgName == "" {
			continue
		}

		var resolved string
		if len(entry) > 1 && entry[1] != nil && string(entry[1]) != "null" {
			_ = json.Unmarshal(entry[1], &resolved)
		}

		var integrity string
		if len(entry) > 3 && entry[3] != nil && string(entry[3]) != "null" {
			_ = json.Unmarshal(entry[3], &integrity)
		}

		nodes = append(nodes, pkgmanager.PackageNode{
			Name:      pkgName,
			Version:   version,
			Resolved:  resolved,
			Integrity: integrity,
			Path:      "node_modules/" + pkgName,
			Depth:     0,
		})

		if len(nodes) > maxBunEntries {
			return nil, fmt.Errorf("too many packages (%d exceeds max %d)", len(nodes), maxBunEntries)
		}
	}

	return nodes, nil
}

func ParseBunLockfile(ctx context.Context) ([]pkgmanager.PackageNode, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	data, err := os.ReadFile("bun.lock")
	if err != nil {
		return nil, fmt.Errorf("reading bun.lock: %w", err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return parseBunLockJSON(data)
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
