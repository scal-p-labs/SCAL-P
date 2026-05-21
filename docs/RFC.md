# SCAL-P — Secure Chain Assurance Layer for Packages

**RFC v0.1 — Why the project looks the way it does**

> Hashes · Policies · Supply Chain Security  
> A verifiable trust layer for the JavaScript ecosystem  
> 2026
> Modern package managers execute code before trust is established. SCAL-P reverses this order

---

## What is SCAL-P?

SCAL-P is a security layer that sits on top of npm, pnpm, yarn, and bun. It does **not** replace your package manager — it wraps it, checks things, and optionally blocks things.

The core idea: make every dependency auditable, traceable, and controllable by policy. No implicit trust.

npm provenance proves origin.
SCAL-P enforces execution policy.

Example:

policy:
```json
{
  "packages": {
    "deny": [{ "pattern": "*-free" }]
  }
}
```

Result:

```cmd
$ scalp install --guarded

policy violations detected:
- lodash-free@1.0.0 (denylist_match: pattern:*-free)

exit: 1
```

## Why this exists

The npm ecosystem has over 2 million packages. That scale created a massive attack surface. Supply chain attacks via malicious packages became a critical vector:

- **event-stream (2018)** — maintainer transferred the package to an attacker who injected Bitcoin-stealing code
- **ua-parser-js (2021)** — compromised maintainer account published malicious versions with cryptominers
- **node-ipc (2022)** — maintainer intentionally shipped destructive protestware
- **colors/faker (2022)** — maintainer deliberately broke widely-used libraries
- **xz-utils (2024)** — sophisticated 2-year social engineering attack to insert a system backdoor

Existing tools don't solve the trust problem:

| Tool | What it does | What it **doesn't** do |
|---|---|---|
| `npm audit` | Detects known CVEs | No authorship verification, no post-install integrity |
| Snyk / Dependabot | Alerts on vulnerabilities | Can't block unauthorized packages by policy |
| `package-lock.json` | Pins exact versions | Doesn't prevent tampering or typosquatting |
| npm provenance (2023) | Links build to repo | Optional adoption, no enforcement |
| **SCAL-P (proposed)** | All of the above + policy + blocking | — |

## Project structure explained

```
scal-p/
├── cmd/scalp/main.go          # CLI entrypoint
├── internal/
│   ├── cli/                   # Command routing, flags, config (install, audit, ci, verify, checksum, stage)
│   ├── policy/                # Policy loading, evaluation, enforcement
│   ├── lockfile/              # .scalp/lockfile.json management
│   ├── hash/                  # SHA-512 hashing (directory, single file, raw bytes)
│   ├── trust/                 # Trust score engine, cache, npm API client
│   ├── reporter/              # JSON, Markdown, and SARIF 2.1.0 reports
│   ├── audit/                 # NDJSON audit logger
│   ├── pkgmanager/            # PackageManager interface + registry
│   ├── npm/                   # npm adapter
│   ├── pnpm/                  # pnpm adapter
│   ├── yarn/                  # yarn (Berry) adapter
│   ├── bun/                   # bun adapter
│   └── version/               # build-time version injection
├── SCALP-RFC-v0.1.txt         # Original RFC (Portuguese)
├── .gitignore
└── README.md
```

Let's walk through each piece and why it exists.

### `cmd/scalp/main.go`

The entrypoint is deliberately tiny. It just calls `cli.Run()` and exits with an error code if something fails. Nothing else belongs here.

**Why minimal?** The entrypoint should never contain logic. It's a switchboard: parse args, delegate, exit.

### `internal/cli/`

Three commands for v0.1:

- **`scalp install`** — calls the package manager with passthrough args. If `--guarded` is set, it evaluates policy and hashes **before** the install runs. After install, it syncs the lockfile.
- **`scalp audit`** — validates the existing lockfile against what's actually in `node_modules`. No network calls, no tarball downloads.
- **`scalp policy check`** — evaluates policy against the current dependency tree without installing anything. Useful in CI.

We don't use cobra or any CLI framework. The parsing is done with `flag` and `os.Args` because:
- Fewer dependencies (zero, actually)
- The command surface is small enough
- It's easier to audit

### `internal/policy/`

The policy engine has three files that mirror the lifecycle:

- **`policy.go`** — defines the Policy struct and handles loading from `.scalp/policy.json`. If the file doesn't exist, it returns a **default permissive policy** (allow + warn + audit). I'm chose JSON over YAML to keep zero external dependencies.
- **`evaluate.go`** — walks the flattened dependency tree and checks each package against allow/deny rules and transitive depth limits.
- **`enforce.go`** — given a list of violations, applies the configured response: `block` (exit 1), `warn` (print, continue), or `log` (silent, just audit).

The default policy is intentional: **no policy file means warn, not fail**. This makes onboarding painless — you get audit data without breaking your workflow.

### `internal/lockfile/`

A SCAL-P specific lockfile (`.scalp/lockfile.json`) separate from npm's `package-lock.json`.

- **`lockfile.go`** — load/save logic. Creates an empty lockfile if none exists.
- **`sync.go`** — two main operations:
  - `SyncWithTree`: after install, hashes each local package directory and records it
  - `VerifyAgainstTree`: for audit, re-hashes local packages and compares

**Why a separate lockfile?** npm's lockfile stores `integrity` as the tarball hash from the registry. SCAL-P stores the hash of the **installed content** on disk. These are different things — a compromised npm registry could serve a bad tarball with a matching integrity field. SCAL-P catches tampering after extraction.

### `internal/hash/`

A single function: `Dir(path)` computes SHA-512 over all regular files in a directory, sorted by name. The output format is `sha512-<base64>`.

**Why hash directories instead of tarballs?** For `audit`, there's no network involved. We hash what's actually on disk. This detects:
- Post-install tampering
- Modified files
- Added/removed files in the package

**Why SHA-512?** It's fast, well-supported in the standard library (`crypto/sha512`), and collision-resistant enough for integrity verification.

### `internal/audit/`

NDJSON logger. Every event (install, policy violation, hash mismatch, missing lockfile entry) gets appended to `.scalp/audit.log`.

**Why NDJSON?** It's simple: one JSON object per line, append-only, grep-friendly, and parsable by any log aggregator (Splunk, ELK, etc.).

### `internal/npm/`

Thin wrapper around the package manager CLI.

- `ResolveViaPackageLockOnly` — runs `npm install --package-lock-only` to resolve deps without installing
- `ParsePackageLock` — reads `package-lock.json` and returns `PackageNode` entries
- `GetDependencyTree` — runs `npm ls --all --json` and parses the output (post-install)
- `RunInstall` — passthrough to `npm install` with whatever args the user provides
- `Flatten` — converts the nested tree into a flat list of `PackageNode` (name, version, resolved, integrity, path, depth)
- `LocalPath` — resolves `node_modules/<name>` for a given package name

For v0.1, only npm is supported for dependency tree resolution. Since v0.2, pnpm, yarn, and bun are fully supported.

## Architecture flow

```
scalp install --guarded
│
├─ 1. Load policy (.scalp/policy.json or default)
├─ 2. Resolve dependencies (npm install --package-lock-only)
├─ 3. Evaluate policy (allow/deny/depth)
├─ 4. If violations → block/warn/log according to policy
├─ 5. Run npm install (passthrough)
└─ 6. Sync lockfile with new hashes
```

## Policy reference

```json
{
  "version": 1,
  "trust": { "mode": "denylist" },
  "packages": {
    "allow": [{ "name": "lodash" }, { "name": "@scope/*" }],
    "deny": [{ "name": "malicious-pkg" }, { "pattern": "*-free" }]
  },
  "transitive": { "max_depth": 5 },
  "enforcement": {
    "on_violation": "block",
    "default_mode": "guarded"
  }
}
```

Modes:
- **allowlist** — only packages explicitly listed are allowed
- **denylist** — specific packages are blocked, everything else is allowed
- **audit-only** — log everything, block nothing

## Threat coverage

| Threat | Detection | Added in |
|---|---|---|
| Compromised account | Hash mismatch against lockfile | v0.1 |
| Protestware / sabotage | Hash mismatch after audit | v0.1 |
| Malicious new version | Blocked by policy (not in allowlist) | v0.1 |
| Transitive supply chain | Recursive tree verification | v0.1 |
| Low-quality packages | Trust score < min_score | v0.2 |
| Release artifact tampering | `scalp verify` binary hash check | v0.2 |
| Staged package tampering | `scalp stage verify` tarball checksum | v0.3 |
| Staged package identity bypass | Tarball package.json extraction vs --stage-id | v0.3 |
| Staged package denylist evasion | Denylist check against extracted tarball name | v0.3 |

Not covered: typosquatting, dependency confusion, static analysis. These are v0.3+ targets.

## Threat Model

SCAL-P assumes:

- The package manager may execute arbitrary code during install
- Registries may serve compromised artifacts
- Maintainer accounts and CI pipelines may be compromised

SCAL-P does NOT assume:

- Trust in package authors
- Trust in registry integrity
- Trust in CI environments

## What's next

- **v0.2** — Sigstore/npm provenance integration, trust score, stricter CI mode, pnpm/yarn/bun support, SARIF 2.1.0 reports, GitHub Code Scanning integration ✓
- **v0.3 (current)** — , `scalp stage verify` for staged package tarballs ✓, denylist bypass prevention ✓, streaming hash verification ✓, Typosquatting detection, dependency confusion, security reports, provenance-based `staged_only` policies
- **v1.0** — SCAL-P Key Registry, IDE plugin, E2E tests

## Design principles

1. **Zero external dependencies** — only the Go standard library. This makes the project easy to build, audit, and vendor.
2. **Don't break the user** — no policy file means allow + warn. SCAL-P shouldn't block your deploy because you forgot a config file.
3. **Audit-first** — every event is logged before any decision is made. You can always see what happened and why.
4. **Passthrough by default, guarded by choice** — `scalp install` without flags is just a transparent wrapper. `--guarded` or `default_mode: guarded` activates enforcement.
5. **Separate lockfile** — SCAL-P's lockfile hashes installed content, not tarballs. They serve different purposes.

## References

- [npm provenance](https://github.com/npm/provenance)
- [Sigstore](https://sigstore.dev)
- [SLSA Framework](https://slsa.dev)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [Socket Security](https://socket.dev)
- [Snyk](https://snyk.io)
- [OWASP Dependency-Check](https://owasp.org)

---

*This is a draft RFC. Feedback and contributions are welcome.*
