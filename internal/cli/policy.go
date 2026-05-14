package cli

import (
	"fmt"
	"log/slog"
	"strings"

	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

func runPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy requires a subcommand")
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand: %s", args[0])
	}
}

func runPolicyCheck(args []string) error {
	fs := newFlagSet("policy-check")
	cfg := &cliConfig{}
	fs.StringVar(&cfg.pm, "pm", "npm", "package manager: npm|pnpm|yarn")
	fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
	fs.BoolVar(&cfg.ci, "ci", false, "set enforcement to block on violation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	applyDefaults(cfg)

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

	if err := pm.Resolve(ctx); err != nil {
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

	enforcement := pol.Enforcement.OnViolation
	if cfg.ci {
		enforcement = policy.EnforceBlock
	}

	if len(violations) == 0 {
		if polInfo.MissingPolicy {
			slog.Warn("policy not found; allowing with audit")
		}
		slog.Info("policy check ok")
		return nil
	}

	return policy.ApplyEnforcement(enforcement, violations)
}
