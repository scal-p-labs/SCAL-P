package pkgmanager

import "fmt"

// NewFunc is a constructor for a PackageManager implementation.
type NewFunc func() PackageManager

// registry maps PM names to their constructors.
var registry = map[string]NewFunc{}

// Register adds a package manager constructor to the registry.
// Each adapter calls this in an init-free registration function.
func Register(name string, fn NewFunc) {
	registry[name] = fn
}

// Get returns the PackageManager for the given name.
func Get(name string) (PackageManager, error) {
	fn, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unsupported package manager: %s", name)
	}
	return fn(), nil
}

// Registered returns the names of all registered package managers.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
