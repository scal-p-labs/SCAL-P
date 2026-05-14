package cli

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

func runInstall(args []string) error {
	fs := newFlagSet("install")
	cfg := &cliConfig{}
	fs.StringVar(&cfg.pm, "pm", "npm", "package manager: npm|pnpm|yarn")
	fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
	fs.BoolVar(&cfg.guarded, "guarded", false, "enforce policy and hash checks before install")
	fs.BoolVar(&cfg.ci, "ci", false, "set enforcement to block on violation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	applyDefaults(cfg)

	pmArgs := fs.Args()
	cfg.pm = strings.ToLower(cfg.pm)
	if !pkgmanager.IsSupported(cfg.pm) {
		return fmt.Errorf("unsupported package manager: %s", cfg.pm)
	}

	pm, err := pkgmanager.Get(cfg.pm)
	if err != nil {
		return err
	}

	ctx := runCtx
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

	mode := pol.Enforcement.DefaultMode
	if cfg.guarded {
		mode = policy.ModeGuarded
	}

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

	if mode == policy.ModeGuarded {
		if err := pm.Resolve(ctx, pmArgs...); err != nil {
			return err
		}

		nodes, err := pm.ParseLockfile(ctx)
		if err != nil {
			return err
		}

		violations, err := policy.Evaluate(pol, nodes)
		if err != nil {
			return err
		}

		if pol.Trust.MinScore > 0 || pol.Trust.RequireHash {
			lf, lfErr := lockfile.Load(ctx, ".scalp/lockfile.json")
			if lfErr == nil {
				scorer := trust.NewScorer(trust.DefaultCacheFile)
				trustVs, tvErr := scorer.Evaluate(ctx, pol, nodes, &lf)
				if tvErr != nil {
					slog.Warn("trust score", "err", tvErr)
				} else {
					violations = append(violations, trustVs...)
				}
			}
		}

		if len(violations) > 0 {
			if err := auditLogger.Log(ctx, policyViolationEvents(violations)); err != nil {
				return err
			}
			if err := policy.ApplyEnforcement(enforcement, violations); err != nil {
				return err
			}
		}
	}

	if err := pm.Install(ctx, pmArgs...); err != nil {
		return err
	}

	depTree, err := pm.GetTree(ctx)
	if err != nil {
		return err
	}

	lfPath := filepath.Join(".scalp", "lockfile.json")
	lf, err := lockfile.Load(ctx, lfPath)
	if err != nil {
		return err
	}

	hashEvents, err := lockfile.SyncWithTree(ctx, &lf, depTree, pm)
	if err != nil {
		return err
	}
	lf.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	if err := lockfile.Save(ctx, lfPath, lf); err != nil {
		return err
	}
	if err := auditLogger.Log(ctx, hashEvents); err != nil {
		return err
	}

	return nil
}
