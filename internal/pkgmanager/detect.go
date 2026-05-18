package pkgmanager

import (
	"fmt"
	"os"
)

const (
	npmLockfile    = "package-lock.json"
	pnpmLockfile   = "pnpm-lock.yaml"
	yarnLockfile   = "yarn.lock"
	bunLockfile    = "bun.lock"
	bunLockfileBin = "bun.lockb"
)

// Detect auto-detects the package manager by checking which lockfile
// exists in the current working directory. Returns an error when the
// situation is ambiguous (both lockfiles) or no lockfile is found.
func Detect() (string, error) {
	hasNPM := fileExists(npmLockfile)
	hasPNPM := fileExists(pnpmLockfile)
	hasYarn := fileExists(yarnLockfile)
	hasBunTxt := fileExists(bunLockfile)
	hasBunBin := fileExists(bunLockfileBin)

	var found []string
	if hasNPM {
		found = append(found, npmLockfile)
	}
	if hasPNPM {
		found = append(found, pnpmLockfile)
	}
	if hasYarn {
		found = append(found, yarnLockfile)
	}
	switch {
	case hasBunTxt:
		found = append(found, bunLockfile)
	case hasBunBin:
		found = append(found, bunLockfileBin)
	}

	if len(found) > 1 {
		return "", fmt.Errorf("multiple lockfiles found (%s); use --pm to disambiguate", joinLockfiles(found))
	}

	switch {
	case hasNPM:
		return "npm", nil
	case hasPNPM:
		return "pnpm", nil
	case hasYarn:
		return "yarn", nil
	case hasBunTxt || hasBunBin:
		return "bun", nil
	default:
		return "", fmt.Errorf("no lockfile found (%s, %s, %s, or %s)",
			npmLockfile, pnpmLockfile, yarnLockfile, bunLockfile)
	}
}

func joinLockfiles(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		result := names[0]
		for _, n := range names[1:] {
			result += ", " + n
		}
		return result
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
