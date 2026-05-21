# `scalp ci` — one command for CI

**RFC v0.2 — Resolve, evaluate, block, install, audit, report — in one shot**

> CI pipelines don't have time for a multi-step dance. `scalp ci` is the equivalent of `install --guarded` + `audit` + a structured report (JSON + SARIF), packaged as a single command that exits 0 or 1.

---

## What it does

```bash
scalp ci [--pm npm|pnpm|yarn|bun] [--output scalp-report.json] [--pr-context fork] [--allow-scripts] [--sarif <path>]
```

Flow, in order:

1. Loads policy (or defaults if missing)
2. Resolves dependencies (lockfile-only, no install)
3. Parses the lockfile and evaluates every package against policy + trust score
4. If any violations → writes report, annotates PR (GitHub Actions), exits 1 (never installs)
5. Installs everything
6. Hashes each installed package (SHA-512), saves to `.scalp/lockfile.json`
7. Audits the lockfile against node_modules (detects tampering, missing packages)
8. Writes a structured JSON report (and optional SARIF 2.1.0 report)

That's it. One command, one exit code, one (or two) reports.

---

## PR context: fork vs internal

`--pr-context` tells `scalp ci` where the code is coming from. Default is `fork` because that's the safest assumption in automated CI.

| Context | `require_hash` | Install scripts | Use case |
|---------|----------------|----------------|----------|
| `fork` (default) | forced on | blocked | PRs from untrusted forks |
| `internal` | as configured | blocked unless `--allow-scripts` | PRs from team members |

**Fork mode** overrides your policy's `require_hash` to `true` regardless of what's in `.scalp/policy.json`. Every package must have a lockfile integrity entry. A fork could have tampered with the lockfile or removed entries, so this is non-negotiable.

**Internal mode** respects your policy. If you trust your team and have a valid `require_hash: false`, it's fine. Scripts are still blocked by default — you opt in with `--allow-scripts` only if you know what you're doing.

---

## Install scripts: blocked by default

npm packages can run arbitrary code during install via `preinstall`, `install`, and `postinstall` scripts. This is one of the most common supply chain attack vectors.

`scalp ci` passes `--ignore-scripts` to the package manager during install. No code runs. No postinstall hooks. No surprise binaries.

To allow scripts (internal context only):

```bash
scalp ci --pr-context internal --allow-scripts
```

This is deliberate: if you need scripts, you should know why. `--allow-scripts` without `--pr-context internal` is still blocked.

---

## Why separate from `install --guarded`?

`scalp install --guarded` is a dev workflow. You're iterating, you want warnings, you might pass custom args to npm/pnpm. The enforcement depends on your policy.

`scalp ci` is a pipeline command. It always blocks on violation. It doesn't pass through arbitrary PM args. It produces a machine-readable report that your CI can parse — no scraping stdout for "policy violation detected".

They share the same evaluation engine. Same trust score, same cache, same everything. The difference is the guardrails and the output.

---

## The JSON report

Written to `--output` (default: `.scalp/ci-report.json`). If you pass `-`, it goes to stdout.

```json
{
  "version": "0.2",
  "passed": false,
  "violations": [
    {
      "package": "evil@1.0",
      "reason": "trust_score: 17/50 (hash:0, maturity:0, dl:10, cves:7)",
      "rule": "min_score:50"
    }
  ],
  "audit": {
    "verified": 42,
    "mismatched": 0,
    "missing": 1
  }
}
```

`passed` is `true` only when both policy evaluation AND hash audit find zero issues.

The `audit` section counts three categories from the hash verification:

| Count | What it means |
|-------|--------------|
| `verified` | On-disk hash matches lockfile |
| `mismatched` | On-disk hash differs from lockfile (tampered or corrupted) |
| `missing` | Package in tree but absent from lockfile, or not installed |

---

## The SARIF report

```bash
scalp ci --sarif .scalp/report.sarif
```

Generates a SARIF 2.1.0 report alongside the JSON report. Each policy violation becomes a SARIF result with:

| SARIF field | Maps from |
|-------------|-----------|
| `ruleId` | Normalized rule name (e.g. `require_hash`, `min_score`) |
| `level` | `error` for most rules, `warning` for `max_depth` |
| `message.text` | Violation reason |
| `locations[].physicalLocation.artifactLocation.uri` | Path to the package in `node_modules/` |

The `results` array is always present (even empty) to satisfy GitHub's `upload-sarif` action requirement.

### GitHub Code Scanning integration

```yaml
- name: Run SCAL-P CI
  run: scalp ci --sarif .scalp/report.sarif

- name: Upload SARIF to GitHub
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .scalp/report.sarif
```

PR annotations are automatically emitted via `::error::` / `::warning::` workflow commands when `GITHUB_ACTIONS=true`, adding inline annotations on the PR diff without requiring `security-events: write`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Everything passed — policy, trust, hashes |
| 1 | Violations found — report has the details |

No other exit codes. If something truly fails (can't resolve, can't install), you get an error message on stderr and exit 1.

---

## What it does NOT do

- Does not check for new versions of packages (use `npm outdated`)
- Does not publish reports anywhere (pipe it yourself)
- Does not run in daemon mode or watch mode
- Does not accept npm/pnpm passthrough args (use `install --guarded` for that)

---

## Example usage in CI

GitHub Actions:

```yaml
- run: scalp ci --output ci-report.json --sarif .scalp/report.sarif
- if: failure()
  run: cat ci-report.json
- if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .scalp/report.sarif
```

GitLab CI:

```yaml
script:
  - scalp ci --output scalp-report.json
artifacts:
  paths:
    - scalp-report.json
```

Local debugging:

```bash
scalp ci --output -
```

---

## Code layout

```
internal/cli/
├── ci.go       — runCi(): parse flags, orchestrate the 8-step flow
└── cli.go      — dispatch: case "ci": return runCi(args[1:])

internal/reporter/
├── json.go     — Report struct, Render(), WriteFile(), AuditFromEvents()
├── json_test.go
├── sarif.go    — SARIF 2.1.0 structs, known rules, RenderSarifFromViolations()
└── sarif_test.go
```

The `reporter` package is independent — it only depends on `policy.Violation` and `audit.Event` structs. No CLI logic leaks in.
