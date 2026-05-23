package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"scal-p/internal/policy"
)

const defaultSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://raw.githubusercontent.com/scal-p-labs/SCAL-P/main/.scalp/policy.schema.json",
  "title": "SCAL-P Policy",
  "description": "Policy file for SCAL-P — controls dependency verification, trust scoring, and enforcement.",
  "type": "object",
  "properties": {
    "$schema": { "type": "string", "description": "JSON Schema reference for editor autocomplete and validation." },
    "version": { "type": "integer", "description": "Policy schema version. Currently only version 1 is supported.", "default": 1, "examples": [1] },
    "trust": {
      "type": "object",
      "description": "Controls which packages are allowed and how trust scoring works.",
      "properties": {
        "mode": { "type": "string", "description": "Package selection mode.", "enum": ["allowlist", "denylist", "audit-only"], "default": "audit-only" },
        "min_score": { "type": "integer", "description": "Minimum trust score (0-80).", "default": 0, "minimum": 0, "maximum": 80, "examples": [60] },
        "require_hash": { "type": "boolean", "description": "When true, any package without a lockfile integrity entry is an automatic violation.", "default": false, "examples": [true] }
      },
      "additionalProperties": false
    },
    "packages": {
      "type": "object",
      "description": "Allow and deny rules for package names and patterns.",
      "properties": {
        "allow": { "type": "array", "description": "List of allowed packages (in allowlist mode).", "items": { "$ref": "#/$defs/packageRule" }, "default": [] },
        "deny": { "type": "array", "description": "List of denied packages (in denylist mode).", "items": { "$ref": "#/$defs/packageRule" }, "default": [] }
      },
      "additionalProperties": false
    },
    "transitive": {
      "type": "object",
      "description": "Limits for transitive (indirect) dependencies.",
      "properties": {
        "max_depth": { "type": "integer", "description": "Maximum allowed nesting depth. 0 means no limit.", "default": 0, "minimum": 0, "examples": [3] }
      },
      "additionalProperties": false
    },
    "enforcement": {
      "type": "object",
      "description": "Controls what happens when a violation is detected.",
      "properties": {
        "on_violation": { "type": "string", "description": "Action to take when a package violates policy.", "enum": ["block", "warn", "log"], "default": "warn" },
        "default_mode": { "type": "string", "description": "Default install mode when --guarded is not passed.", "enum": ["guarded", "passthrough"], "default": "passthrough" }
      },
      "additionalProperties": false
    }
  },
  "required": ["version"],
  "additionalProperties": false,
  "$defs": {
    "packageRule": {
      "type": "object",
      "description": "A rule matching one or more packages by name, pattern, version, or checksum.",
      "properties": {
        "name": { "type": "string", "description": "Exact package name to match.", "examples": ["lodash", "@scope/package"] },
        "pattern": { "type": "string", "description": "Glob pattern for matching packages.", "examples": ["*-free", "@scope/*", "*substr*"] },
        "versions": { "type": "string", "description": "Version constraint (npm semver range).", "examples": ["^4.0.0", ">=1.0.0"] },
        "checksum": { "type": "string", "description": "Expected SHA-512 integrity hash.", "examples": ["sha512-a1b2c3d4..."] }
      },
      "oneOf": [
        { "required": ["name"] },
        { "required": ["pattern"] }
      ],
      "additionalProperties": false
    }
  }
}
`

func runInit(ctx context.Context, args []string) error {
	fs := newFlagSet("init")
	minimal := fs.Bool("minimal", false, "create minimal policy (bare skeleton)")
	strict := fs.Bool("strict", false, "create strict policy (require_hash, min_score, block)")

	if err := parseFlagSet(fs, args); err != nil {
		return err
	}

	scalpDir := ".scalp"
	if err := os.MkdirAll(scalpDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", scalpDir, err)
	}

	var pol policy.Policy

	switch {
	case *strict:
		pol = strictPolicy()
	case *minimal:
		pol = minimalPolicy()
	default:
		pol = policy.DefaultPolicy()
	}

	polJSON, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	policyPath := filepath.Join(scalpDir, "policy.json")
	if err := os.WriteFile(policyPath, polJSON, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", policyPath, err)
	}
	slog.Info("Created .scalp/policy.json")

	schemaPath := filepath.Join(scalpDir, "policy.schema.json")
	if err := os.WriteFile(schemaPath, []byte(defaultSchemaJSON), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", schemaPath, err)
	}
	slog.Info("Created .scalp/policy.schema.json")

	lockfilePath := filepath.Join(scalpDir, "lockfile.json")
	if err := os.WriteFile(lockfilePath, []byte("{}\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", lockfilePath, err)
	}
	slog.Info("Created .scalp/lockfile.json")

	auditPath := filepath.Join(scalpDir, "audit.log")
	if err := os.WriteFile(auditPath, nil, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", auditPath, err)
	}
	slog.Info("Created .scalp/audit.log")

	cacheDir := filepath.Join(scalpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", cacheDir, err)
	}
	slog.Info("Created .scalp/cache/")

	return nil
}

func minimalPolicy() policy.Policy {
	return policy.Policy{
		Version: 1,
	}
}

func strictPolicy() policy.Policy {
	return policy.Policy{
		Version: 1,
		Trust: policy.Trust{
			Mode:        policy.TrustDenylist,
			MinScore:    60,
			RequireHash: true,
		},
		Packages: policy.Packages{
			Deny: []policy.PackageRule{
				{Pattern: "*-free"},
				{Name: "colors"},
				{Name: "faker"},
				{Name: "node-ipc"},
				{Name: "event-stream"},
			},
		},
		Transitive: policy.Transitive{
			MaxDepth: 3,
		},
		Enforcement: policy.Enforcement{
			OnViolation: policy.EnforceBlock,
			DefaultMode: policy.ModeGuarded,
		},
	}
}
