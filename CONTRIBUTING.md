# Contributing to SCAL-P

First off, thanks for wanting to contribute. SCAL-P is a security tool, so every line of code matters. This guide exists to keep the codebase consistent, auditable, and safe.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Workflow](#pull-request-workflow)
- [Architecture Overview](#architecture-overview)

---

## Code of Conduct

This project follows a **no-drama policy**. Be respectful, assume good intent, and focus on the code. Harassment, trolling, and personal attacks will not be tolerated.

---

## Getting Started

If you're new:
- Start with issues labeled `good first issue`
- Read `internal/policy` first (core logic)
- Run tests locally before making changes

---

## How to Contribute

### Reporting bugs

Open an issue with:

- `scalp version` output
- Steps to reproduce (minimal npm project + policy file)
- Expected vs actual behavior
- SCAL-P audit log (`.scalp/audit.log`) if applicable

### Suggesting features

Open an issue describing:

- The problem you're solving (not just the solution)
- How it fits SCAL-P's scope (policy, hashing, auditing)
- Example CLI usage or policy snippet

### Submitting code

See [Pull Request Workflow](#pull-request-workflow).

---

## Development Setup

**Requirements:**

- Go 1.22+
- npm (for end-to-end tests)
- `golangci-lint` (optional, for linting)

**Clone and build:**

```bash
git clone https://github.com/<owner>/scal-p
cd scal-p
make build
```

**Run unit tests:**

```bash
make test
```

**Run end-to-end tests (requires npm):**

```bash
make e2e
```

**Run all checks before submitting:**

```bash
go build ./cmd/scalp
go test -count=1 ./...
golangci-lint run ./...
```

---

## Code Style

SCAL-P follows Go conventions with a few project-specific rules.

### General

- **Zero external dependencies** — only the Go standard library. Every import must be justified.
- Files use tabs for indentation (Go standard).
- Lines should be readable; no hard line limit, but keep functions short.

### Idioms

| Style | Preferred | Avoid |
|---|---|---|
| **Defaults** | `cmp.Or(field, "default")` | `if field == "" { field = "default" }` |
| **Sorting** | `slices.SortFunc` | `sort.Slice` |
| **Iteration** | `for i := range n` | `for i := 0; i < n; i++` |
| **Error wrapping** | `fmt.Errorf("doing X: %w", err)` | `fmt.Errorf("doing X: "+err.Error())` |
| **Multi-error** | `errors.Join(err1, err2)` | Manual string concatenation |
| **Observability** | `log/slog` for warnings and info | `fmt.Println` for observability |
| **User output** | Direct `fmt.Fprintln` or `slog` | Neither is strictly wrong; use slog for structured data, fmt for plain messages |

### Context

- Every function that performs I/O (filesystem, exec, network) takes `context.Context` as the **first argument**.
- Check context at function entry via `ctxutil.Check(ctx)`.
- Context cancellations must be respected inside loops.

### Errors

- **Never silence errors with `_ =`**. Every error must be handled or explicitly returned.
- Wrap errors with context: `fmt.Errorf("read policy: %w", err)`.
- Use `errors.Join` when combining multiple errors (e.g., Close + operation errors).
- Return errors to the caller; never panic (except for truly unrecoverable states).

### Concurrency

- Use `sync.Mutex` for protecting shared state (e.g., audit logger).
- Document which goroutine owns a given resource.
- Avoid global mutable state.

### What to avoid

- ❌ `interface{}` — use `any` or generics
- ❌ `init()` — unless absolutely necessary
- ❌ Global mutable state
- ❌ `os.Exit` outside of `main`
- ❌ Excessively complex one-liners that hurt readability

### Naming

- Exported types and functions must have doc comments.
- Unexported functions need doc comments only if their purpose isn't obvious.
- Acronyms are uppercase: `HTTP`, `URL`, `ID`, `JSON`, `SHA512`.

---

## Security Guidelines

SCAL-P is part of the software supply chain. Contributions must not:

- Introduce non-deterministic behavior in hashing or policy evaluation
- Execute untrusted code implicitly
- Expand the attack surface (e.g., new external integrations) without strong justification

If your change affects:
- dependency resolution
- hashing
- policy enforcement
- execution flow

You must include:
- tests covering adversarial scenarios
- a clear explanation of security implications

---

## Scope

SCAL-P focuses on:
- Policy enforcement
- Dependency integrity (hashing)
- Auditing

SCAL-P does NOT aim to:
- Replace package managers
- Perform deep static analysis
- Act as a vulnerability scanner

Contributions outside this scope may be declined.

---

## Testing

Testing is split into two tiers.

### Unit tests (`go test ./...`)

- Live alongside the code as `*_test.go` files.
- Table-driven tests preferred for logic-heavy functions.
- Filesystem-dependent tests use `t.TempDir()`.
- Tests that need to control external commands use the mock pattern:
  - Call `npm.SetExecCommand(mockFn)` in the test
  - Restore with `t.Cleanup(func() { npm.SetExecCommand(original) })`

### End-to-end tests (`go test -tags=e2e ./...`)

- Build and run the `scalp` binary in isolated temp directories.
- Require `npm` to be installed.
- Test real-world scenarios: blocking, tampering, allowlist, reproducibility.
- Tagged with `//go:build e2e` so they're excluded from normal `go test`.
- Run with:

```bash
go test -tags=e2e -count=1 -timeout=120s ./e2e/
```

### Coverage expectations

| Area | Minimum |
|---|---|
| `internal/policy` (logic) | 90%+ |
| `internal/hash` | 85%+ |
| `internal/audit` | 80%+ |
| `internal/lockfile` | 80%+ |
| `internal/npm` (pure logic) | 85%+ |
| `internal/npm` (exec) | Mock-covered |

>[Note]: Coverage is a guideline, not a goal. Tests must validate behavior, not just lines

PRs that add code should include corresponding tests. Bug fixes must include a regression test.

---

## Pull Request Workflow

### Before opening

1. Fork the repo and create a branch from `main`.
2. Make your changes.
3. Run all checks:

```bash
make build
make test
golangci-lint run ./...
```

4. If you changed behavior, update or add tests.
5. Write a clear commit message (see below).

### Commit messages

```
package: short description (50 chars max)

Longer explanation if needed. Wrap at 72 chars.
- Bullet points for multiple changes
- Reference issues: "Fixes #123"
```

Examples:

```
npm: pass install args to ResolveViaPackageLockOnly

The guarded mode was resolving the dependency tree without considering
the packages the user passed on the command line (e.g., `is-odd`). This
meant policy violations for those packages were never detected.
Fixes #42.
```

```
lockfile: detect missing package directories

Previously VerifyAgainstTree silently skipped packages whose directories
didn't exist on disk. Now a `package_not_installed` violation is raised
with a corresponding audit event.
```

Or use your preferred method of committing.

### PR checklist

- [ ] Code compiles (`go build ./cmd/scalp`)
- [ ] Tests pass (`go test -count=1 ./...`)
- [ ] Lint passes (`golangci-lint run ./...`)
- [ ] New code has tests (unit and/or e2e)
- [ ] Bug fixes include a regression test
- [ ] Commit messages follow the convention
- [ ] No external dependencies added (stdlib only)
- [ ] Context propagation is correct (first argument pattern)
- [ ] Errors are wrapped, not silenced

### Review process

1. Maintainer reviews within 3 business days.
2. CI must pass (build + unit tests + lint + e2e).
3. At least one approval required before merge.
4. Squash merge preferred (keeps history clean).

---

## Architecture Overview

```
cmd/scalp/main.go              # Entrypoint — calls cli.Run()
internal/cli/                  # CLI routing, flags, commands
internal/policy/               # Policy loading, evaluation, enforcement
internal/lockfile/             # .scalp/lockfile.json management
internal/hash/                 # SHA-512 directory hashing
internal/audit/                # NDJSON audit logger
internal/npm/                  # Package manager wrapper + package-lock parser
internal/ctxutil/              # Context helpers
internal/version/              # Build-time version injection (ldflags)
```

See [docs/RFC.md](docs/RFC.md) for the full design rationale.

---

## Questions?

Open a [discussion](https://github.com/carlosedujs/scal-p/discussions) or check `docs/RFC.md`.
