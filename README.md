# SCAL-P (PoC v0.1)

> This active development PoC is not production-ready. Expect breaking changes and security issues. Use at your own risk.

Secure Chain Assurance Layer for Packages. Policy, hashing, and audit log for npm.

Zero external dependencies — only the Go standard library.

## Build

```bash
make build # build: .bin/scalp
```

## Usage

```bash
./scalp install --pm npm --guarded    # resolve + evaluate policy before installing
./scalp install --pm npm              # passthrough, then sync lockfile
./scalp audit --pm npm                # verify lockfile vs node_modules
./scalp policy check --pm npm         # check policy against resolved tree
```

## How `--guarded` works

1. Load policy (`.scalp/policy.json` or default)
2. Resolve dependencies **without installing** (`npm install --package-lock-only`)
3. Evaluate policy (allowlist/denylist/depth)
4. Decision: **block** (exit 1), **warn** (print, continue), or **log** (silent)
5. If passed, run real `npm install`
6. Sync lockfile (`.scalp/lockfile.json`) with hashes of installed packages

## Policy

Default path: `.scalp/policy.json`.

**No policy file = allow + warn + audit** (onboarding-friendly).

Example:

```json
{
  "version": 1,
  "trust": { "mode": "denylist" },
  "packages": {
    "deny": [
      { "name": "malicious-pkg" },
      { "pattern": "*-free" }
    ]
  },
  "enforcement": {
    "on_violation": "block",
    "default_mode": "guarded"
  }
}
```

### Modes

| `trust.mode` | Behavior |
|---|---|
| `allowlist` | Only listed packages allowed |
| `denylist` | Listed packages blocked, others allowed |
| `audit-only` | Log everything, block nothing |

### Enforcement

| `on_violation` | Behavior |
|---|---|
| `block` | Prints violations and exits with code 1 |
| `warn` | Prints violations and continues (exit 0) |
| `log` | Silently logs to audit |

## Audit Log

`.scalp/audit.log` in NDJSON format — append-only, grep-friendly.

## Lockfile

`.scalp/lockfile.json` — generated automatically after `install`. Contains SHA-512 hashes of package directory contents on disk.

## Project structure

```
scalp/
├── cmd/scalp/main.go              # entrypoint
├── internal/
│   ├── cli/                       # CLI command routing
│   ├── policy/                    # policy loading, evaluation, enforcement
│   ├── lockfile/                  # .scalp/lockfile.json management
│   ├── hash/                      # SHA-512 directory hashing
│   ├── audit/                     # NDJSON audit logger
│   └── npm/                       # package manager wrapper + package-lock parser
```

See `RFC.md` for the full rationale.
