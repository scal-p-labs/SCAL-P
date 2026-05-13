package cli

import (
	"context"
	"log/slog"
	"strings"

	"scal-p/internal/audit"
	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

func runAudit(args []string) error {
    fs := newFlagSet("audit")
    cfg := &cliConfig{}
    fs.StringVar(&cfg.pm, "pm", "npm", "package manager: npm|pnpm")
    fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
    fs.BoolVar(&cfg.ci, "ci", false, "set enforcement to block on violation")

    if err := fs.Parse(args); err != nil {
        return err
    }
    applyDefaults(cfg)

    cfg.pm = strings.ToLower(cfg.pm)
	pm, err := pkgmanager.Get(cfg.pm)
	if err != nil {
		return err
	}

	ctx := context.Background()
	pol, polInfo, err := policy.Load(ctx, cfg.policyPath)
	if err != nil {
		return err
	}

	auditLogger := audit.NewLogger(".scalp/audit.log")
	defer func() {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("closing audit log", "err", err)
		}
	}()

    enforcement := pol.Enforcement.OnViolation
    if cfg.ci {
        enforcement = policy.EnforceBlock
    }

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
		if err := auditLogger.Log(ctx, []audit.Event{policyMissingEvent()}); err != nil {
			return err
		}
	}

	lf, err := lockfile.Load(ctx, ".scalp/lockfile.json")
	if err != nil {
		return err
	}

	depTree, err := pm.GetTree(ctx)
	if err != nil {
		return err
	}

	violations, events, err := lockfile.VerifyAgainstTree(ctx, &lf, depTree, pm)
	if err != nil {
		return err
	}

	if pol.Trust.MinScore > 0 || pol.Trust.RequireHash {
		nodes := pkgmanager.Flatten(depTree)
		scorer := trust.NewScorer(trust.DefaultCacheFile)
		trustVs, tvErr := scorer.Evaluate(ctx, pol, nodes, &lf)
		if tvErr != nil {
			slog.Warn("trust score", "err", tvErr)
		} else {
			violations = append(violations, trustVs...)
		}
	}

	if err := auditLogger.Log(ctx, events); err != nil {
		return err
	}

	if len(violations) > 0 {
		return policy.ApplyEnforcement(enforcement, violations)
	}
	slog.Info("audit ok")
	return nil
}
