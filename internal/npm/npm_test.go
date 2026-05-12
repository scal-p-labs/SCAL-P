package npm_test

import (
	"context"
	"testing"

	"scal-p/internal/npm"
)

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
		got := npm.IsSupported(tt.pm)
		if got != tt.supp {
			t.Errorf("IsSupported(%q) = %v, want %v", tt.pm, got, tt.supp)
		}
	}
}

func TestLocalPath(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"lodash", "node_modules/lodash"},
		{"@scope/pkg", "node_modules/@scope/pkg"},
		{"", "node_modules/"},
	}
	for _, tt := range tests {
		got := npm.LocalPath(tt.name)
		if got != tt.want {
			t.Errorf("LocalPath(%q) = %q, want %q", tt.name, got, tt.want)
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
	}
	for _, tt := range tests {
		got := npm.IsScoped(tt.name)
		if got != tt.scoped {
			t.Errorf("IsScoped(%q) = %v, want %v", tt.name, got, tt.scoped)
		}
	}
}

func TestFlatten(t *testing.T) {
	t.Run("nil dependencies", func(t *testing.T) {
		tree := npm.DependencyTree{Name: "root", Version: "1.0"}
		nodes := npm.Flatten(tree)
		if nodes != nil {
			t.Errorf("expected nil, got %+v", nodes)
		}
	})

	t.Run("empty dependencies", func(t *testing.T) {
		tree := npm.DependencyTree{
			Name:         "root",
			Version:      "1.0",
			Dependencies: map[string]npm.DependencyRef{},
		}
		nodes := npm.Flatten(tree)
		if len(nodes) != 0 {
			t.Errorf("expected 0 nodes, got %d", len(nodes))
		}
	})

	t.Run("nested tree", func(t *testing.T) {
		tree := npm.DependencyTree{
			Name:    "root",
			Version: "1.0",
			Dependencies: map[string]npm.DependencyRef{
				"a": {
					Version: "1.0",
					Dependencies: map[string]npm.DependencyRef{
						"b": {Version: "2.0"},
					},
				},
			},
		}

		nodes := npm.Flatten(tree)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d: %+v", len(nodes), nodes)
		}
		if nodes[0].Name != "a" || nodes[0].Version != "1.0" || nodes[0].Depth != 0 {
			t.Errorf("unexpected first node: %+v", nodes[0])
		}
		if nodes[1].Name != "b" || nodes[1].Version != "2.0" || nodes[1].Depth != 1 {
			t.Errorf("unexpected second node: %+v", nodes[1])
		}
	})
}

func TestResolveNode(t *testing.T) {
	deps := map[string]npm.DependencyRef{
		"a": {Version: "1.0"},
	}

	t.Run("found", func(t *testing.T) {
		ref, err := npm.ResolveNode(deps, "a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref.Version != "1.0" {
			t.Errorf("expected 1.0, got %s", ref.Version)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := npm.ResolveNode(deps, "b")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("nil deps", func(t *testing.T) {
		_, err := npm.ResolveNode(nil, "a")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParsePackageLock(t *testing.T) {
	t.Run("v3 lockfile", func(t *testing.T) {
		nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v3.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}
		// Map iteration order is non-deterministic; check by name
		byName := map[string]npm.PackageNode{}
		for _, n := range nodes {
			byName[n.Name] = n
		}
		if n, ok := byName["lodash"]; !ok {
			t.Error("missing lodash node")
		} else if n.Version != "4.17.21" {
			t.Errorf("lodash version: expected 4.17.21, got %s", n.Version)
		}
		if n, ok := byName["is-odd"]; !ok {
			t.Error("missing is-odd node")
		} else if n.Version != "3.0.1" {
			t.Errorf("is-odd version: expected 3.0.1, got %s", n.Version)
		}
	})

	t.Run("v2 lockfile with scoped and nested deps", func(t *testing.T) {
		nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v2.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(nodes) != 3 {
			t.Fatalf("expected 3 nodes, got %d", len(nodes))
		}
		byName := map[string]npm.PackageNode{}
		for _, n := range nodes {
			byName[n.Name] = n
		}
		if n, ok := byName["@scope/name"]; !ok {
			t.Error("missing @scope/name node")
		} else if n.Depth != 0 {
			t.Errorf("@scope/name depth: expected 0, got %d", n.Depth)
		}
		if n, ok := byName["express"]; !ok {
			t.Error("missing express node")
		} else if n.Depth != 0 {
			t.Errorf("express depth: expected 0, got %d", n.Depth)
		}
		if n, ok := byName["accepts"]; !ok {
			t.Error("missing accepts node")
		} else if n.Depth != 1 {
			t.Errorf("accepts depth: expected 1, got %d", n.Depth)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := npm.ParsePackageLock(context.Background(), "nonexistent.json")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestExtractName_nested(t *testing.T) {
	// Regression test for bug #1: nested transitive deps extract incorrect name
	nodes, err := npm.ParsePackageLock(context.Background(), "testdata/lockfile-v2.json")
	if err != nil {
		t.Fatal(err)
	}

	var nestedFound bool
	for _, n := range nodes {
		if n.Depth == 1 {
			if n.Name != "accepts" {
				t.Errorf("nested dep: expected 'accepts', got '%s'", n.Name)
			}
			nestedFound = true
		}
	}
	if !nestedFound {
		t.Error("no nested dependency found in lockfile-v2.json")
	}
}
