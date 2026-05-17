# SCAL-P — Secure Chain Assurance Layer for Packages

> Policy enforcement, dependency hashing, trust scoring, and audit for npm and pnpm.
> Zero external dependencies — only the Go standard library.

```bash
scalp install --guarded                            # resolve → evaluate → block → install → sync
scalp audit                                         # verify lockfile hashes match node_modules
scalp audit --report audit-report.md                # audit + Markdown report
scalp audit --report - --artifact <f> --checksum <f> # audit + binary verify + stdout report
scalp ci                                            # single CI command: all of the above + JSON report
scalp verify --artifact <file> --checksum <file>     # verify release artifact
```

---

## Why

npm/pnpm run arbitrary code during install. SCAL-P flips the order: policy before trust, hash after install, audit always.

v0.2 adds trust scores (numeric risk dimension), pnpm support, a dedicated CI command, and the ability to verify SCAL-P's own releases (dogfooding).

---

## Install

Download from [releases](https://github.com/CarlosEduJs/SCAL-P/releases), or build:

```bash
make build
```

---

## Commands

| Command | What it does |
|---------|-------------|
| `install --guarded` | Resolve lockfile, evaluate policy + trust scores, block if violations, install, hash-sync lockfile |
| `install` | Passthrough install, then hash-sync lockfile |
| `audit` | Verify `.scalp/lockfile.json` hashes match `node_modules` on disk |
| `audit --report <path>` | Audit + generate Markdown report (use `--report -` for stdout) |
| `audit --artifact <f> --checksum <f>` | Audit + optionally verify a binary artifact in the same run |
| `ci` | Resolve → evaluate → block → install → audit → structured JSON report. Always blocks. |
| `policy check` | Evaluate policy against resolved dependencies without installing |
| `verify --artifact <file> --checksum <file>` | Verify release artifact SHA-512 against checksums file |
| `checksum <files...>` | Generate SHA-512 checksums for files |

### Audit report

```bash
scalp audit --report audit-report.md
```

Generates a human-readable Markdown report with:

| Section | Contents |
|---------|----------|
| Header | Tool version, policy status, package manager, pass/fail |
| Summary | Total packages, verified/mismatched/missing counts, trust violations, CVEs |
| Hash Verification | Per-package status |
| Trust Scores | Per-package breakdown (hash, maturity, downloads, CVEs) with verdict |
| CVEs | Vulnerability table |
| Binary Verification | Artifact hash comparison (when `--artifact` + `--checksum` given) |
| Policy | Full policy JSON |
| Violations | All violations with rule and reason |

Flags:

- `--report <path>` — output file path (`.md`). Use `--report -` for stdout.
- `--artifact <file>` — optional binary artifact to verify alongside packages
- `--checksum <file>` — checksums file for binary verification

The report is designed to be auditable, versionable, easy to attach in CI, easy to review in PRs, and easy to sign/attest later. Format detection by extension — `.md` today, `.json`/`.adoc` ready to add.

### CI mode

```bash
scalp ci --pr-context fork --output ci-report.json
```

Flags:
- `--pr-context fork` (default): forces `require_hash`, blocks install scripts
- `--pr-context internal`: respects policy, scripts blocked unless `--allow-scripts`
- `--output`: path to JSON report (default `.scalp/ci-report.json`)

### Binary verify (dogfooding)

```bash
scalp checksum scalp_linux_amd64.tar.gz scalp_darwin_amd64.tar.gz > checksums.txt
scalp verify --artifact scalp_linux_amd64.tar.gz --checksum checksums.txt --ci
```

SCAL-P verifies its own releases — same engine, same format.

---

## Policy

Default: `.scalp/policy.json`. No file = warn + audit-only (safe default).

```json
{
  "$schema": ".scalp/policy.schema.json",
  "version": 1,
  "trust": {
    "mode": "allowlist",
    "min_score": 60,
    "require_hash": true
  },
  "packages": {
    "allow": [{ "name": "lodash" }],
    "deny": [{ "pattern": "*-free" }]
  },
  "transitive": { "max_depth": 5 },
  "enforcement": {
    "on_violation": "block",
    "default_mode": "guarded"
  }
}
```

Full schema at `.scalp/policy.schema.json` — editor autocomplete included.

### Trust score (0–80)

Four factors: hash verified (30), version >= 1.0.0 (15), weekly npm downloads (0–20), no active CVEs (0/15).

Offline-first: network failure = half points, not zero. `require_hash`: missing lockfile entry = automatic violation.

### Modes

| `trust.mode` | Behavior |
|---|---|
| `allowlist` | Only listed packages allowed |
| `denylist` | Listed packages blocked, others allowed |
| `audit-only` | Log everything, block nothing |

### Enforcement

| `on_violation` | Behavior |
|---|---|
| `block` | Exit 1 |
| `warn` | Print + continue |
| `log` | Silent pass |

---

## Package managers

npm (default) and pnpm supported. Select with `--pm`:

```bash
scalp install --pm npm              # npm (default)
scalp install --pm pnpm             # pnpm
scalp ci --pm pnpm                  # CI with pnpm
scalp audit --pm pnpm               # audit pnpm lockfile
```

The PM flag must come before the subcommand's own arguments:

```bash
scalp install --pm pnpm --guarded   # guarded install with pnpm
scalp install --pm npm --guarded    # same with npm (explicit)
```

---

## Architecture

```
cmd/scalp/main.go              # entrypoint → cli.Run()
internal/
├── cli/                       # command routing (install, audit, ci, verify, checksum)
├── policy/                    # policy loading, evaluation, enforcement
├── lockfile/                  # .scalp/lockfile.json management + hash verification
├── hash/                      # SHA-512 hashing (directory + single file)
├── trust/                     # trust score engine, cache, npm API client
├── reporter/                  # JSON + Markdown reports (CI, audit)
├── audit/                     # NDJSON audit logger
├── ctxutil/                   # context helpers
├── pkgmanager/                # PackageManager interface + registry
├── npm/                       # npm adapter
├── pnpm/                      # pnpm adapter
└── version/                   # build-time version injection
```

---

## Audit log

`.scalp/audit.log` — NDJSON, append-only. Every install, audit, and verify produces events.

---

## Lockfile

`.scalp/lockfile.json` — auto-generated after install. SHA-512 hashes of each package directory.

---

## JSON Schema

`.scalp/policy.schema.json` — Draft 2020-12 schema for `policy.json`. VS Code and other editors pick it up from the `$schema` field automatically.

---

See `docs/` for detailed RFCs on trust scoring, CI mode, and binary verify.
