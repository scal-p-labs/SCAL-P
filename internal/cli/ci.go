package cli

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/reporter"
	"scal-p/internal/trust"
)

func runCi(args []string) error {
	fs := newFlagSet("ci")
	cfg := &cliConfig{}
	fs.StringVar(&cfg.pm, "pm", "npm", "package manager: npm|pnpm")
	fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
	output := fs.String("output", ".scalp/ci-report.json", "report output path")

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

	ctx := context.Background()
	pol, polInfo, err := policy.Load(ctx, cfg.policyPath)
	if err != nil {
		return err
	}

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
	}

	if err := pm.Resolve(ctx, fs.Args()...); err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	nodes, err := pm.ParseLockfile(ctx)
	if err != nil {
		return fmt.Errorf("parse lockfile: %w", err)
	}

	violations, err := policy.Evaluate(pol, nodes)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
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
		if err := reporter.WriteReport(*output, false, violations, nil); err != nil {
			slog.Warn("report", "err", err)
		}
		return policy.ApplyEnforcement(policy.EnforceBlock, violations)
	}

	if err := pm.Install(ctx, fs.Args()...); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	depTree, err := pm.GetTree(ctx)
	if err != nil {
		return fmt.Errorf("get tree: %w", err)
	}

	lfPath := filepath.Join(".scalp", "lockfile.json")
	lf, err := lockfile.Load(ctx, lfPath)
	if err != nil {
		return fmt.Errorf("load lockfile: %w", err)
	}

	hashEvents, err := lockfile.SyncWithTree(ctx, &lf, depTree, pm)
	if err != nil {
		return fmt.Errorf("sync lockfile: %w", err)
	}

	lf.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	if err := lockfile.Save(ctx, lfPath, lf); err != nil {
		return fmt.Errorf("save lockfile: %w", err)
	}

	auditViolations, auditEvents, err := lockfile.VerifyAgainstTree(ctx, &lf, depTree, pm)
	if err != nil {
		return fmt.Errorf("verify tree: %w", err)
	}

	allEvents := append(hashEvents, auditEvents...)
	passed := len(auditViolations) == 0

	if err := reporter.WriteReport(*output, passed, auditViolations, allEvents); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	if !passed {
		return fmt.Errorf("ci failed: %d hash violations", len(auditViolations))
	}

	return nil
}
