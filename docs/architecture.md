# Architecture

**How the pieces fit together — data flow from CLI to audit log**

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

## Data flow (stage verify)

```
CLI (scalp stage verify --stage-id <pkg>)
│
├─ 1. Load policy ─────────────────────── internal/policy/
│    │  .scalp/policy.json
│    └─> Policy struct
│
├─ 2. Stream tarball from stdin ───────── crypto/sha512 (streaming)
│    │  io.TeeReader(os.Stdin, sha512.New())
│    │  Simultaneously hash + decompress
│    └─> Tarball data → gzip.NewReader → tar.NewReader
│
├─ 3. Extract package identity ────────── archive/tar
│    │  Find package/package.json
│    │  Parse JSON name field
│    └─> Package name (denylist target)
│
├─ 4. Verify checksum ─────────────────── crypto/sha512
│    │  Compare h.Sum() against --checksum
│    └─> Violation if mismatch
│
├─ 5. Verify stage ID ─────────────────── internal/cli/stage.go
│    │  Compare extracted name against --stage-id
│    └─> Violation if mismatch (bypass prevention)
│
├─ 6. Denylist check ──────────────────── internal/policy/
│    │  Check extracted name against package deny rules
│    │  Name match (EqualFold) + pattern match
│    └─> Violation if matched
│
├─ 7. SARIF output ────────────────────── internal/reporter/
│    │  RenderSarifFromViolations with stage ID as artifact URI
│    └─> .sarif file (if --sarif provided)
│
└─ 8. Enforce ─────────────────────────── internal/policy/
     │  --ci → block, otherwise policy on_violation
     └─> Exit 0 or 1
```

---

## Component diagram

```
┌─────────────┐
│    CLI      │  internal/cli/ — command routing, flag parsing
│  cli.go     │  install, audit, ci, verify, checksum, stage
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
                    │  hash        │  hash.Dir() / hash.File() / hash.Bytes()
                    │  lockfile    │  .scalp/lockfile.json
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  audit       │  NDJSON logger
                    │  reporter    │  structured JSON + SARIF 2.1.0
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
├─ 5. If violations → annotate PR, write report, optional SARIF → exit 1
├─ 6. Install (--ignore-scripts in fork context)
├─ 7. Hash sync (hash.Dir → .scalp/lockfile.json)
├─ 8. Verify against tree (detect tampering)
├─ 9. Write report (.scalp/ci-report.json or stdout) + optional SARIF
└─ 10. Exit 0 if no violations, 1 otherwise
```

The JSON report is always written — even on failure. CI can pick it up as an artifact. The SARIF report is written when `--sarif <path>` is provided.

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
