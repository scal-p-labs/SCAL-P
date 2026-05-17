package pkgmanager

import (
	"fmt"
	"os"
)

const (
	npmLockfile  = "package-lock.json"
	pnpmLockfile = "pnpm-lock.yaml"
)

// Detect auto-detects the package manager by checking which lockfile
// exists in the current working directory. Returns an error when the
// situation is ambiguous (both lockfiles) or no lockfile is found.
func Detect() (string, error) {
	hasNPM := fileExists(npmLockfile)
	hasPNPM := fileExists(pnpmLockfile)

	switch {
	case hasNPM && hasPNPM:
		return "", fmt.Errorf("both %s and %s found; use --pm to disambiguate", npmLockfile, pnpmLockfile)
	case hasNPM:
		return "npm", nil
	case hasPNPM:
		return "pnpm", nil
	default:
		return "", fmt.Errorf("no lockfile found (%s or %s)", npmLockfile, pnpmLockfile)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
