package cli

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/npm"
	"scal-p/internal/pnpm"
	"scal-p/internal/policy"
	"scal-p/internal/version"
)

func init() {
	npm.Register()
	pnpm.Register()
}

func Run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "version", "-v", "--version":
		slog.Info("version", "version", version.Version, "commit", version.Commit, "date", version.Date)
		return nil
	case "install":
		return runInstall(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "ci":
		return runCi(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "checksum":
		return runChecksum(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "help", "-h", "--help":
		return usageError()
	default:
		return fmt.Errorf("unknown command: %s\n%s", args[0], usageText())
	}
}

func usageError() error {
	return errors.New(usageText())
}

func usageText() string {
	return strings.TrimSpace(`scalp - Secure Chain Assurance Layer for Packages

Usage:
  scalp version
  scalp ci [flags]
  scalp install [flags] [--] [pm args...]
  scalp audit [flags]
  scalp policy check [flags]
  scalp verify --artifact <file> --checksum <file> [flags]
  scalp checksum [--output <file>] <files...>

Commands:
  ci            resolve, evaluate, install, audit — single CI step (always blocks)
  install       install packages via npm/pnpm with optional enforcement
  audit         validate lockfile vs node_modules
  policy check  evaluate policy without installing
  verify        verify release artifact against checksums file
  checksum      generate SHA-512 checksums for files

Global flags:
  --pm string       package manager: npm|pnpm (default "npm")
  --guarded         enforce policy and hash checks before install
  --policy string   policy path (default ".scalp/policy.json")
  --ci              set enforcement to block on violation

CI flags:
  --pr-context string    PR context: fork (default) or internal
  --allow-scripts        allow install scripts to run (internal only)
  --output string        report output path (default ".scalp/ci-report.json")
`)
}

func policyMissingEvent() audit.Event {
	return audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     "policy_missing",
		Status:    "warn",
		Reason:    "policy_not_found",
	}
}

func policyViolationEvents(violations []policy.Violation) []audit.Event {
	events := make([]audit.Event, 0, len(violations))
	for _, v := range violations {
		events = append(events, audit.Event{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Event:     "policy_violation",
			Package:   v.PackageID,
			Status:    "blocked",
			Reason:    v.Reason,
			Rule:      v.Rule,
		})
	}
	return events
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}