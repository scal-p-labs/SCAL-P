package reporter

import (
	"fmt"
	"strings"

	"scal-p/internal/audit"
	"scal-p/internal/policy"
)

// RenderAuditMarkdown produces a Markdown audit report from AuditData.
func RenderAuditMarkdown(data AuditData) ([]byte, error) {
	var b strings.Builder

	writeHeader(&b, data)
	writeSummary(&b, data)
	writeHashDetails(&b, data)
	writeTrustScores(&b, data)
	writeCVEs(&b, data)
	writeBinaryResults(&b, data)
	writePolicyBlock(&b, data)
	writeViolations(&b, data)
	writeRawLog(&b, data)
	writeFooter(&b)

	return []byte(b.String()), nil
}

func writeHeader(b *strings.Builder, d AuditData) {
	fmt.Fprintf(b, "# Audit Report\n\n")

	fmt.Fprintf(b, "**Tool:** scalp %s (%s)\n", d.Version, d.Commit)
	fmt.Fprintf(b, "**Date:** %s\n", d.Timestamp)
	fmt.Fprintf(b, "**Policy:** %s", d.PolicyPath)
	if d.PolicyLoaded {
		fmt.Fprint(b, " ✓ loaded")
	} else {
		fmt.Fprint(b, " ✗ missing")
	}
	fmt.Fprint(b, "\n")
	fmt.Fprintf(b, "**Package Manager:** %s\n", d.PM)

	statusText := "✅ PASSED"
	if d.Status == "failed" {
		statusText = fmt.Sprintf("❌ FAILED (%d violation(s))", len(d.Violations))
	}
	fmt.Fprintf(b, "**Status:** %s\n\n", statusText)
}

func writeSummary(b *strings.Builder, d AuditData) {
	verified, mismatched, missing := countHashEvents(d.Events)

	fmt.Fprint(b, "## Summary\n\n")
	fmt.Fprint(b, "| Metric | Value |\n")
	fmt.Fprint(b, "|--------|-------|\n")
	fmt.Fprintf(b, "| Total packages | %d |\n", d.TotalPackages)
	fmt.Fprintf(b, "| ✓ Verified | %d |\n", verified)
	fmt.Fprintf(b, "| ✗ Mismatched | %d |\n", mismatched)
	fmt.Fprintf(b, "| ✗ Missing | %d |\n", missing)
	fmt.Fprintf(b, "| Trust violations | %d |\n", countTrustViolations(d.Violations))
	fmt.Fprintf(b, "| CVEs | %d |\n", countCVEs(d.CVEs))
	if len(d.BinaryResults) > 0 {
		fmt.Fprintf(b, "| Binary artifacts | %d |\n", len(d.BinaryResults))
	}
	fmt.Fprint(b, "\n")
}

func countHashEvents(events []audit.Event) (verified, mismatched, missing int) {
	for _, e := range events {
		if e.Event == "hash_verified" || (e.Event == "hash_check" && e.HashMatch) {
			verified++
		} else if e.Status == "mismatch" {
			mismatched++
		} else if e.Status == "missing" {
			missing++
		}
	}
	return
}

func countTrustViolations(violations []policy.Violation) int {
	var n int
	for _, v := range violations {
		if strings.HasPrefix(v.Rule, "min_score:") {
			n++
		}
	}
	return n
}

func countCVEs(cves map[string][]string) int {
	return len(cves)
}

func writeHashDetails(b *strings.Builder, d AuditData) {
	fmt.Fprint(b, "## Hash Verification\n\n")

	// Build a lookup: pkg@version → status from events
	type hashRow struct {
		pkg    string
		status string
	}
	var rows []hashRow

	// Derive from events — we don't have the lockfile here, so just show
	// status from events. The integrity column is omitted when unavailable.
	for _, e := range d.Events {
		if e.Event != "hash_check" && e.Event != "hash_verified" && e.Event != "hash_missing" {
			continue
		}
		status := "—"
		switch {
		case e.HashMatch:
			status = "✓ verified"
		case e.Status == "missing":
			status = "✗ missing"
		case e.Status == "mismatch":
			status = "✗ mismatch"
		}
		rows = append(rows, hashRow{pkg: e.Package, status: status})
	}

	if len(rows) == 0 {
		fmt.Fprint(b, "_No packages checked._\n\n")
		return
	}

	fmt.Fprint(b, "| Package | Status |\n")
	fmt.Fprint(b, "|---------|--------|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| %s | %s |\n", r.pkg, r.status)
	}
	fmt.Fprint(b, "\n")
}

func writeTrustScores(b *strings.Builder, d AuditData) {
	fmt.Fprint(b, "## Trust Scores\n\n")

	if len(d.TrustScores) == 0 {
		fmt.Fprint(b, "_No trust scores computed._\n\n")
		return
	}

	fmt.Fprint(b, "| Package | Hash | Maturity | Downloads | CVEs | Total | Verdict |\n")
	fmt.Fprint(b, "|---------|------|----------|-----------|------|-------|---------|\n")

	for _, s := range d.TrustScores {
		verdict := "✓ pass"
		for _, v := range d.Violations {
			if v.PackageID == s.PackageID && strings.HasPrefix(v.Rule, "min_score:") {
				verdict = "✗ fail"
				break
			}
		}
		fmt.Fprintf(b, "| %s | %d | %d | %d | %d | %d | %s |\n",
			s.PackageID,
			s.Breakdown.HashVerified,
			s.Breakdown.Maturity,
			s.Breakdown.Downloads,
			s.Breakdown.NoCVEs,
			s.Total,
			verdict,
		)
	}
	fmt.Fprint(b, "\n")
}

func writeCVEs(b *strings.Builder, d AuditData) {
	fmt.Fprint(b, "## Vulnerabilities (CVEs)\n\n")

	if len(d.CVEs) == 0 {
		fmt.Fprint(b, "_No CVEs found._\n\n")
		return
	}

	fmt.Fprint(b, "| Package | Severity |\n")
	fmt.Fprint(b, "|---------|----------|\n")
	for pkg, severities := range d.CVEs {
		for _, sev := range severities {
			fmt.Fprintf(b, "| %s | %s |\n", pkg, sev)
		}
	}
	fmt.Fprint(b, "\n")
}

func writeBinaryResults(b *strings.Builder, d AuditData) {
	if len(d.BinaryResults) == 0 {
		return
	}

	fmt.Fprint(b, "## Binary Verification\n\n")
	fmt.Fprint(b, "| Artifact | Status | Expected Hash | Actual Hash |\n")
	fmt.Fprint(b, "|----------|--------|---------------|-------------|\n")

	for _, br := range d.BinaryResults {
		status := "✓ verified"
		if !br.Passed {
			status = "✗ mismatch"
		}
		fmt.Fprintf(b, "| %s | %s | `%s` | `%s` |\n",
			br.Artifact, status, br.Expected, br.Actual)
	}
	fmt.Fprint(b, "\n")
}

func writePolicyBlock(b *strings.Builder, d AuditData) {
	fmt.Fprint(b, "## Policy\n\n")

	if d.PolicyJSON == "" {
		fmt.Fprint(b, "_No policy data._\n\n")
		return
	}

	fmt.Fprintf(b, "```json\n%s\n```\n\n", d.PolicyJSON)
}

func writeViolations(b *strings.Builder, d AuditData) {
	if len(d.Violations) == 0 {
		return
	}

	fmt.Fprint(b, "## Violations\n\n")
	fmt.Fprint(b, "| Package | Rule | Reason |\n")
	fmt.Fprint(b, "|---------|------|--------|\n")

	for _, v := range d.Violations {
		fmt.Fprintf(b, "| %s | %s | %s |\n", v.PackageID, v.Rule, v.Reason)
	}
	fmt.Fprint(b, "\n")
}

func writeRawLog(b *strings.Builder, d AuditData) {
	if len(d.Events) == 0 {
		return
	}

	fmt.Fprint(b, "## Audit Events\n\n")
	fmt.Fprint(b, "```\n")
	for _, e := range d.Events {
		line := formatEvent(e)
		fmt.Fprintln(b, line)
	}
	fmt.Fprint(b, "```\n\n")
}

func formatEvent(e audit.Event) string {
	// Format: ts event pkg status [reason] [rule]
	// Keep it compact for the raw log section.
	var parts []string
	parts = append(parts, e.Timestamp, e.Event)
	if e.Package != "" {
		parts = append(parts, e.Package)
	}
	parts = append(parts, e.Status)
	if e.Reason != "" {
		parts = append(parts, e.Reason)
	}
	if e.Rule != "" {
		parts = append(parts, "rule="+e.Rule)
	}
	return strings.Join(parts, " ")
}

func writeFooter(b *strings.Builder) {
	fmt.Fprint(b, "---\n\n")
	fmt.Fprint(b, "*Report generated by scalp. This report is auditable, versionable, and PR-reviewable.*\n")
}


