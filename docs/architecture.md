# Architecture

**How the pieces fit together — data flow from CLI to audit log. v0.3 adds yarn (Berry) and bun adapters.**

> SCAL-P is not a daemon, not a proxy, not a plugin. It's a CLI tool that wraps your package manager. Every invocation is stateless: load policy, resolve, evaluate, act, log, exit.

---

## Data flow (guarded install)

```
CLI (scalp install --guarded)
│
├─ 1. Load policy ─────────────────────── internal/policy/
│    │  .scalp/policy.json
│    │  default if missing
│    └─> Policy struct
│
├─ 2. Resolve ─────────────────────────── internal/npm|pnpm|yarn|bun/
│    │  npm install --package-lock-only
│    │  pnpm install --lockfile-only
│    │  yarn install --mode=skip-build
│    │  bun install --frozen-lockfile
│    └─> PM-specific lockfile
│
├─ 3. Parse lockfile ──────────────────── internal/pkgmanager/
│    │  adapter.ParseLockfile(ctx)
│    │  npm: reads package-lock.json
│    │  pnpm: reads pnpm-lock.yaml
│    │  yarn: reads yarn.lock
│    │  bun: reads bun.lock
│    └─> []PackageNode
│
├─ 4. Evaluate policy ─────────────────── internal/policy/
│    │  policy.Evaluate(pol, nodes)
│    │  allowlist / denylist / audit-only
│    │  transitive max_depth
│    └─> []Violation
│
├─ 5. Evaluate trust score ────────────── internal/trust/
│    │  scorer.Evaluate(pol, nodes, lockfile)
│    │  4 factors: hash, maturity, downloads, CVEs
│    │  cache: .scalp/cache/trust.json
│    │  npm API: api.npmjs.org (degraded offline)
│    └─> []Violation (appended to policy violations)
│
├─ 6. Enforce ─────────────────────────── internal/policy/
│    │  ApplyEnforcement(mode, violations)
│    │  block → exit 1
│    │  warn  → log + continue
│    │  log   → silent
│    └─> audit events logged
│
├─ 7. Install ─────────────────────────── internal/npm|pnpm|yarn|bun/
│    │  npm install / pnpm install / yarn install / bun install
│    │  --ignore-scripts in CI/fork context
│    └─> node_modules/ populated
│
├─ 8. Get dependency tree ─────────────── internal/pkgmanager/
│    │  adapter.GetTree(ctx)
│    │  npm ls --all --json
│    │  pnpm ls --json --depth Infinity
│    │  yarn list --json --depth=Infinity --all (or lockfile fast path)
│    │  bun pm ls --all --json (or lockfile fast path)
│    └─> DependencyTree
│
├─ 9. Hash sync ───────────────────────── internal/lockfile/
│    │  SyncWithTree(ctx, lf, tree, pm)
│    │  hash.Dir() for each package
│    │  SHA-512 of every file in directory
│    └─> .scalp/lockfile.json updated
│
└─ 10. Audit log ──────────────────────── internal/audit/
     │  audit.Logger.Log(ctx, events)
     │  NDJSON append-only
     └─> .scalp/audit.log
```

---

## Component diagram

```
┌─────────────┐
│    CLI      │  internal/cli/ — command routing, flag parsing
│  cli.go     │  install, audit, ci, verify, checksum
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌────────────────────────────┐
│  pkgmanager │────▶│  npm / pnpm / yarn / bun   │  adapter pattern
│  interface  │     │  adapter                   │  exec.CommandContext for PM
└──────┬──────┘     └────────────────────────────┘
       │
       ▼
┌─────────────┐     ┌──────────────────┐
│  policy     │────▶│  policy.Evaluate │  allow/deny/transitive rules
│  .json      │     │  trust.Evaluate  │  hash + maturity + downloads + CVEs
└─────────────┘     └──────┬───────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  enforcement │  block / warn / log
                    └──────┬───────┘
                           │
                           ▼ (if passed)
                    ┌──────────────┐
                    │  hash        │  hash.Dir() / hash.File()
                    │  lockfile    │  .scalp/lockfile.json
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  audit       │  NDJSON logger
                    │  reporter    │  structured JSON (CI)
                    └──────────────┘
```

---

## Package manager adapter

Every package manager implements the same interface:

```
PackageManager
├── Name() string
├── Resolve(ctx, args...) error
├── ParseLockfile(ctx) ([]PackageNode, error)
├── Install(ctx, args...) error
├── GetTree(ctx) (DependencyTree, error)
└── LocalPath(name) string
```

Currently implemented: npm, pnpm, yarn (Berry v2+), bun. The registry in `internal/pkgmanager/registry.go` maps names to constructors, called from `cli.init()`.

To add a new PM: implement the interface, register it, done.

---

## Trust score pipeline

```
scorer.Evaluate(ctx, policy, nodes, lockfile)
│
├─ Load cache (.scalp/cache/trust.json)
├─ Fetch CVEs (npm audit --json OR injected mock)
│
├─ For each PackageNode:
│  ├─ Hash verified?        → 30 or 0 pts
│  ├─ Version >= 1.0.0?     → 15 or 0 pts
│  ├─ Downloads (cache/API) → 0-20 pts (half if unknown)
│  └─ CVEs (audit/cache)    → 15 or 0 pts (half if unknown)
│  │   require_hash?        → hard violation if no hash
│  └─ Score < min_score?    → violation
│
├─ Update cache
└─ Save cache
```

---

## CI command flow

```
scalp ci
│
├─ 1. Load policy
├─ 2. Resolve (lockfile-only)
├─ 3. Parse lockfile
├─ 4. Evaluate policy + trust
├─ 5. If violations → write report → exit 1 (never installs)
├─ 6. Install (--ignore-scripts in fork context)
├─ 7. Hash sync (hash.Dir → .scalp/lockfile.json)
├─ 8. Verify against tree (detect tampering)
├─ 9. Write report (.scalp/ci-report.json or stdout)
└─ 10. Exit 0 if no violations, 1 otherwise
```

The report is always written — even on failure. CI can pick it up as an artifact.

---

## File layout

```
.scalp/
├── policy.json           ← your policy (checked in)
├── policy.schema.json    ← JSON Schema (checked in)
├── lockfile.json         ← auto-generated hashes
├── ci-report.json        ← last CI run
├── cache/
│   └── trust.json        ← download counts, CVEs (TTL 7 days)
└── audit.log             ← append-only event log
```

Policy and schema are checked into version control. Everything else is local state — never commit `.scalp/lockfile.json`, `.scalp/cache/`, or `.scalp/audit.log`.

---

## Design constraints

- **Zero external Go dependencies** — stdlib only. No framework, no SDK, no ORM.
- **No daemon** — every invocation is stateless. Load, evaluate, act, exit.
- **Offline-first** — network is a cache amplifier, not a requirement.
- **Deterministic** — same inputs (policy, lockfile, cache) produce the same outputs.
