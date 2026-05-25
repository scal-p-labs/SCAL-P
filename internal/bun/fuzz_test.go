package bun

import (
	"testing"
)

func FuzzParseBunLockJSON(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"lockfileVersion":1,"packages":{}}`,
		`{"lockfileVersion":1,"packages":{"lodash@4.17.21":[{"name":"lodash","version":"4.17.21"},"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",null,"sha512-test=="]}}`,
		`{"lockfileVersion":1,"packages":{"@scope/pkg@1.0.0":[{"name":"@scope/pkg","version":"1.0.0"},"https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",null,"sha512-test=="]}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := parseBunLockJSON(data)
		if err != nil {
			return
		}
		for _, n := range nodes {
			if n.Name == "" {
				t.Errorf("empty name in parsed node")
			}
		}
	})
}

func FuzzParseBunLockText(f *testing.F) {
	seeds := []string{
		"",
		"# comment",
		"lodash@4.17.21:\n  version: 4.17.21\n  resolution: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\n  integrity: sha512-test==\n",
		"\"@scope/pkg\"@1.0.0:\n  version: 1.0.0\n  resolution: https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := parseBunLockText(data)
		if err != nil {
			return
		}
		for _, n := range nodes {
			if n.Name == "" {
				t.Errorf("empty name in parsed node")
			}
		}
	})
}
