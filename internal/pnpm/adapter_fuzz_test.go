package pnpm

import (
	"testing"
)

// FuzzParseLockfileYAML tests that parseLockfileYAML never panics on arbitrary input.
// The parser must either return valid nodes or a non-nil error — never panic.
//
// Seed corpus values represent real-world lockfile structures.
func FuzzParseLockfileYAML(f *testing.F) {
	seeds := []string{
		"",
		"lockfileVersion: '9.0'\npackages:\n",
		"lockfileVersion: '9.0'\npackages:\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-test==}\n    dev: false\n",
		"lockfileVersion: '6.0'\npackages:\n  /is-odd/3.0.1:\n    resolution:\n      integrity: sha512-test==\n    dev: false\n",
		"invalid yaml {{{{\npackages:\n  /a/b:\n    resolution: {integrity: x}\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := parseLockfileYAML(data)
		if err != nil {
			// Error is expected for most random inputs.
			// Just verify we don't panic.
			return
		}
		// If parsing succeeded, validate basic invariants.
		for _, n := range nodes {
			if n.Name == "" {
				t.Errorf("empty name in parsed node")
			}
			if n.Version == "" {
				t.Errorf("empty version in parsed node for %s", n.Name)
			}
		}
	})
}
