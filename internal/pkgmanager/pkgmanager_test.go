package pkgmanager_test

import (
	"testing"

	"scal-p/internal/pkgmanager"
)

func TestFlatten(t *testing.T) {
	t.Run("nil dependencies returns nil", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{Name: "root", Version: "1.0"}
		nodes := pkgmanager.Flatten(tree)
		if nodes != nil {
			t.Errorf("expected nil, got %v", nodes)
		}
	})

	t.Run("empty dependencies returns nil", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{
			Name:         "root",
			Version:      "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{},
		}
		nodes := pkgmanager.Flatten(tree)
		if len(nodes) != 0 {
			t.Errorf("expected 0 nodes, got %d", len(nodes))
		}
	})

	t.Run("flat tree", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{
			Name:    "root",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"a": {Version: "1.0"},
				"b": {Version: "2.0"},
			},
		}
		nodes := pkgmanager.Flatten(tree)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}
		for _, n := range nodes {
			if n.Depth != 0 {
				t.Errorf("expected depth 0, got %d for %s", n.Depth, n.Name)
			}
		}
	})

	t.Run("nested tree tracks depth", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{
			Name:    "root",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"a": {
					Version: "1.0",
					Dependencies: map[string]pkgmanager.DependencyRef{
						"b": {Version: "2.0"},
					},
				},
			},
		}
		nodes := pkgmanager.Flatten(tree)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}

		byName := map[string]pkgmanager.PackageNode{}
		for _, n := range nodes {
			byName[n.Name] = n
		}
		if byName["a"].Depth != 0 {
			t.Errorf("a: expected depth 0, got %d", byName["a"].Depth)
		}
		if byName["b"].Depth != 1 {
			t.Errorf("b: expected depth 1, got %d", byName["b"].Depth)
		}
	})

	t.Run("duplicate versions are distinct entries", func(t *testing.T) {
		tree := pkgmanager.DependencyTree{
			Name:    "root",
			Version: "1.0",
			Dependencies: map[string]pkgmanager.DependencyRef{
				"lodash": {
					Version: "4.17.21",
					Dependencies: map[string]pkgmanager.DependencyRef{
						"lodash": {Version: "3.10.1"},
					},
				},
			},
		}
		nodes := pkgmanager.Flatten(tree)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}

		var foundV3, foundV4 bool
		for _, n := range nodes {
			if n.Name == "lodash" && n.Version == "3.10.1" && n.Depth == 1 {
				foundV3 = true
			}
			if n.Name == "lodash" && n.Version == "4.17.21" && n.Depth == 0 {
				foundV4 = true
			}
		}
		if !foundV3 {
			t.Error("missing lodash@3.10.1 at depth 1")
		}
		if !foundV4 {
			t.Error("missing lodash@4.17.21 at depth 0")
		}
	})
}

func TestIsSupported(t *testing.T) {
	tests := []struct {
		pm   string
		supp bool
	}{
		{"npm", true},
		{"pnpm", true},
		{"yarn", true},
		{"pip", false},
		{"cargo", false},
		{"", false},
	}
	for _, tt := range tests {
		got := pkgmanager.IsSupported(tt.pm)
		if got != tt.supp {
			t.Errorf("IsSupported(%q) = %v, want %v", tt.pm, got, tt.supp)
		}
	}
}

func TestIsScoped(t *testing.T) {
	tests := []struct {
		name   string
		scoped bool
	}{
		{"@scope/pkg", true},
		{"lodash", false},
		{"@scope", true},
		{"", false},
		{"@@double", true},
	}
	for _, tt := range tests {
		got := pkgmanager.IsScoped(tt.name)
		if got != tt.scoped {
			t.Errorf("IsScoped(%q) = %v, want %v", tt.name, got, tt.scoped)
		}
	}
}
