package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"scal-p/internal/audit"
	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/reporter"
	"scal-p/internal/trust"
	"scal-p/internal/version"
)

func runAudit(ctx context.Context, args []string) error {
	fs := newFlagSet("audit")
	cfg := &cliConfig{}
	fs.StringVar(&cfg.pm, "pm", "npm", "package manager: npm|pnpm")
	fs.StringVar(&cfg.policyPath, "policy", ".scalp/policy.json", "policy path")
	fs.BoolVar(&cfg.ci, "ci", false, "set enforcement to block on violation")
	fs.StringVar(&cfg.report, "report", "", "report output path (e.g. audit-report.md)")
	fs.StringVar(&cfg.artifact, "artifact", "", "binary artifact to verify (optional)")
	fs.StringVar(&cfg.checksumFile, "checksum", "", "checksums file for binary verification")

	if err := fs.Parse(args); err != nil {
		return err
	}
	applyDefaults(cfg)

	cfg.pm = strings.ToLower(cfg.pm)
	pm, err := pkgmanager.Get(cfg.pm)
	if err != nil {
		return err
	}

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

	var scorer *trust.Scorer
	if pol.Trust.MinScore > 0 || pol.Trust.RequireHash {
		nodes, flattenErr := pkgmanager.Flatten(depTree)
		if flattenErr != nil {
			slog.Warn("flatten tree", "err", flattenErr)
		} else {
			scorer = trust.NewScorer(trust.DefaultCacheFile)
			trustVs, tvErr := scorer.Evaluate(ctx, pol, nodes, &lf)
			if tvErr != nil {
				slog.Warn("trust score", "err", tvErr)
			} else {
				violations = append(violations, trustVs...)
			}
		}
	}

	binaryResults, err := runBinaryVerify(ctx, cfg, &events, &violations)
	if err != nil {
		slog.Warn("binary verify", "err", err)
	}

	if err := auditLogger.Log(ctx, events); err != nil {
		return err
	}

	if cfg.report != "" {
		if err := generateAuditReport(cfg, pol, polInfo, depTree, events, violations, scorer, binaryResults); err != nil {
			slog.Warn("audit report", "err", err)
		}
	}

	if len(violations) > 0 {
		return policy.ApplyEnforcement(enforcement, violations)
	}
	slog.Info("audit ok")
	return nil
}

// runBinaryVerify performs optional binary verification and returns results.
func runBinaryVerify(ctx context.Context, cfg *cliConfig, events *[]audit.Event, violations *[]policy.Violation) ([]reporter.BinaryVerifyResult, error) {
	if cfg.artifact == "" || cfg.checksumFile == "" {
		return nil, nil
	}

	result, err := verifyArtifact(ctx, cfg.artifact, cfg.checksumFile)
	if err != nil {
		return nil, err
	}

	status := "verified"
	if !result.matched {
		status = "mismatch"
	}
	*events = append(*events, audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     "binary_verify",
		Package:   result.filename,
		Status:    status,
		HashMatch: result.matched,
	})

	if !result.matched {
		*violations = append(*violations, policy.Violation{
			PackageID: result.filename,
			Reason:    fmt.Sprintf("hash_mismatch: expected %s, got %s", result.expected, result.actual),
			Rule:      "binary_verify",
		})
	}

	return []reporter.BinaryVerifyResult{{
		Artifact: result.filename,
		Passed:   result.matched,
		Expected: result.expected,
		Actual:   result.actual,
	}}, nil
}

func generateAuditReport(
	cfg *cliConfig,
	pol policy.Policy,
	polInfo policy.LoadInfo,
	depTree pkgmanager.DependencyTree,
	events []audit.Event,
	violations []policy.Violation,
	scorer *trust.Scorer,
	binaryResults []reporter.BinaryVerifyResult,
) error {
	nodes, _ := pkgmanager.Flatten(depTree)
	totalPkgs := len(nodes)

	policyJSON, _ := json.MarshalIndent(pol, "", "  ")

	var scores []trust.PackageScore
	var cves map[string][]string
	if scorer != nil {
		scores = scorer.Scores()
		cves = scorer.CVEs()
	}

	status := "passed"
	if len(violations) > 0 {
		status = "failed"
	}

	data := reporter.AuditData{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Version:       version.Version,
		Commit:        version.Commit,
		PolicyPath:    cfg.policyPath,
		PolicyLoaded:  !polInfo.MissingPolicy,
		PolicyJSON:    string(policyJSON),
		PM:            cfg.pm,
		Status:        status,
		TotalPackages: totalPkgs,
		Events:        events,
		Violations:    violations,
		TrustScores:   scores,
		CVEs:          cves,
		BinaryResults: binaryResults,
		Enforcement:   string(pol.Enforcement.OnViolation),
	}

	return reporter.WriteAuditReport(cfg.report, data)
}
