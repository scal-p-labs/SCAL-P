package yarn

import (
	"testing"
)

func FuzzParseYarnLockYAML(f *testing.F) {
	seeds := []string{
		"",
		"__metadata:\n  version: 6\n",
		"lodash@npm:4.17.21:\n  version: 4.17.21\n  resolution: {tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz}\n  checksum: sha512-test==\n",
		"\"@scope/pkg@npm:1.0.0\":\n  version: 1.0.0\n  resolution: {tarball: https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz}\n  checksum: sha512-test==\n",
		"@scope/pkg@virtual:abc123#npm:1.0.0:\n  version: 1.0.0\n",
		"left-pad@npm:1.3.0:\n  version: 1.3.0\n",
		"packages:\n  lodash@npm:4.17.21:\n    version: 4.17.21\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := parseYarnLockYAML(data)
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
