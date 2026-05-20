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
	"scal-p/internal/version"
)

func runCi(ctx context.Context, args []string) error {
	fs := newFlagSet("ci")
	cfg := &cliConfig{}
	fs.StringVar(&cfg.pm, "pm", "", "package manager (auto-detected from lockfile)")
	fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
	output := fs.String("output", ".scalp/ci-report.json", "report output path")
	prContext := fs.String("pr-context", "fork", "PR context: fork (default) or internal")
	allowScripts := fs.Bool("allow-scripts", false, "allow install scripts to run (internal only)")
	fs.StringVar(&cfg.sarifReport, "sarif", "", "output path for SARIF report")

	if err := parseFlagSet(fs, args); err != nil {
		return err
	}
	applyDefaults(cfg)

	cfg.pm = strings.ToLower(cfg.pm)
	if !pkgmanager.IsSupported(cfg.pm) {
		return fmt.Errorf("unsupported package manager: %s", cfg.pm)
	}

	prType := strings.ToLower(*prContext)
	if prType != "fork" && prType != "internal" {
		return fmt.Errorf("invalid PR context: %s (must be fork or internal)", *prContext)
	}

	pm, err := pkgmanager.Get(cfg.pm)
	if err != nil {
		return err
	}

	pol, polInfo, err := policy.Load(ctx, cfg.policyPath)
	if err != nil {
		return err
	}

	if polInfo.MissingPolicy {
		slog.Warn("policy not found; allowing with audit")
	}

	if prType == "fork" {
		pol.Trust.RequireHash = true
		slog.Info("fork context: require_hash enforced, install scripts blocked")
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
		if lfErr != nil {
			slog.Warn("trust score: no lockfile, using offline-only factors", "err", lfErr)
		} else {
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
		if cfg.sarifReport != "" {
			if err := writeSarif(cfg.sarifReport, false, violations); err != nil {
				slog.Warn("sarif report", "err", err)
			}
		}
		return policy.ApplyEnforcement(policy.EnforceBlock, violations)
	}

	installArgs := fs.Args()
	if prType == "fork" || !*allowScripts {
		installArgs = append([]string{"--ignore-scripts"}, installArgs...)
	}

	if err := pm.Install(ctx, installArgs...); err != nil {
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

	allViolations := append(violations, auditViolations...)

	if cfg.sarifReport != "" {
		if err := writeSarif(cfg.sarifReport, passed, allViolations); err != nil {
			slog.Warn("sarif report", "err", err)
		}
	}

	if !passed {
		return fmt.Errorf("ci failed: %d hash violations", len(auditViolations))
	}

	return nil
}

func writeSarif(path string, passed bool, violations []policy.Violation) error {
	data, err := reporter.RenderSarifFromViolations(
		version.Version,
		time.Now().UTC().Format(time.RFC3339),
		passed,
		violations,
	)
	if err != nil {
		return fmt.Errorf("render sarif: %w", err)
	}
	return reporter.WriteFile(path, data)
}
