package policy

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"scal-p/internal/ctxutil"
)

// Policy defines the verification and enforcement configuration.
type Policy struct {
    Version      int          `json:"version"`
    Trust        Trust        `json:"trust"`
    Packages     Packages     `json:"packages"`
    Transitive   Transitive   `json:"transitive"`
    Enforcement  Enforcement  `json:"enforcement"`
}

// Trust controls the trust evaluation mode and optional minimum trust score.
type Trust struct {
    Mode        string `json:"mode"`
    MinScore    int    `json:"min_score,omitempty"`
    RequireHash bool   `json:"require_hash,omitempty"`
}

// Packages contains allow and deny rules.
type Packages struct {
    Allow []PackageRule `json:"allow"`
    Deny  []PackageRule `json:"deny"`
}

// PackageRule defines a package match rule.
type PackageRule struct {
    Name     string `json:"name"`
    Versions string `json:"versions"`
    Checksum string `json:"checksum"`
    Pattern  string `json:"pattern"`
}

// Transitive defines limits for transitive dependencies.
type Transitive struct {
    MaxDepth int `json:"max_depth"`
}

// Enforcement defines what happens on policy violations.
type Enforcement struct {
    OnViolation string `json:"on_violation"`
    DefaultMode string `json:"default_mode"`
}

// LoadInfo describes how a policy was loaded.
type LoadInfo struct {
    MissingPolicy bool
}

const (
    ModeGuarded     = "guarded"
    ModePassthrough = "passthrough"

    TrustAllowlist = "allowlist"
    TrustDenylist  = "denylist"
    TrustAuditOnly = "audit-only"

    EnforceBlock = "block"
    EnforceWarn  = "warn"
    EnforceLog   = "log"
)

// Load reads a policy from disk or returns a default policy.
func Load(ctx context.Context, path string) (Policy, LoadInfo, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return Policy{}, LoadInfo{}, err
	}

	info := LoadInfo{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			info.MissingPolicy = true
			return DefaultPolicy(), info, nil
		}
		return Policy{}, info, fmt.Errorf("read policy: %w", err)
	}

    var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return Policy{}, info, fmt.Errorf("invalid policy JSON: %w", err)
	}
	applyPolicyDefaults(&pol)
	return pol, info, nil
}

// DefaultPolicy returns the permissive default policy.
func DefaultPolicy() Policy {
    return Policy{
        Version: 1,
        Trust: Trust{
            Mode: TrustAuditOnly,
        },
        Enforcement: Enforcement{
            OnViolation: EnforceWarn,
            DefaultMode: ModePassthrough,
        },
    }
}

func applyPolicyDefaults(pol *Policy) {
	if pol.Version == 0 {
		pol.Version = 1
	}
	pol.Trust.Mode = cmp.Or(pol.Trust.Mode, TrustAuditOnly)
	pol.Enforcement.OnViolation = cmp.Or(pol.Enforcement.OnViolation, EnforceWarn)
	pol.Enforcement.DefaultMode = cmp.Or(pol.Enforcement.DefaultMode, ModePassthrough)
}
