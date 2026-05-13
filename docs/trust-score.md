# Trust Score — how it works

**RFC v0.2 — Offline-first, deterministic, no magic**

> A package with 1M downloads/week and no known CVEs should not be treated the same as a random 0.0.1 from an unknown author. Trust score gives you a numeric dimension on top of allow/deny.

---

## What it is

A deterministic score (0–80) for each dependency, computed from four factors:

| Factor | Max pts | Source | Works offline? |
|--------|---------|--------|----------------|
| Hash verified | 30 | `.scalp/lockfile.json` | yes |
| Version >= 1.0.0 | 15 | lockfile | yes |
| Weekly downloads | 20 | `api.npmjs.org` | degraded (10 pts) |
| No active CVEs | 15 | `npm audit --json` | degraded (7 pts) |

If the score is below `trust.min_score` in your policy, it's a violation — same as a denied package.

```json
{
  "trust": {
    "mode": "allowlist",
    "min_score": 60,
    "require_hash": true
  }
}
```

`min_score: 0` (default) means trust scoring is disabled. No behavior change from v0.1.

---

## Unknown vs Bad

This is the key distinction that makes the score fair when offline.

**Unknown** = we can't check right now (no internet, no audit data, no cache). You get **half points** as a penalty, not zero. No one likes uncertainty, but we don't assume the worst.

**Bad** = we checked and the data says it's bad. You get **0**.

| Factor | Unknown (offline/no data) | Bad (checked & failed) |
|--------|---------------------------|----------------------|
| Downloads | 10 pts | 0 pts (< 100/week) |
| CVEs | 7 pts | 0 pts (open CVEs found) |

Download example:
- Offline, no cache → 10 pts (unknown)
- Online, 50 downloads/week → 0 pts (bad — low popularity)
- Online, 500K downloads/week → 20 pts (good)

CVE example:
- Pre-install (no node_modules to audit) → 7 pts (unknown)
- `npm audit` ran, found CVEs for this package → 0 pts
- `npm audit` ran, no CVEs → 15 pts

---

## Hard fail: `require_hash`

```json
{ "trust": { "require_hash": true } }
```

When `require_hash` is true, any package that lacks a lockfile integrity entry is an **automatic violation** — regardless of total score. The violation says `hash_required` and the package is skipped from trust scoring entirely.

This is your "supply chain minimum" switch. If a package wasn't installed through SCAL-P's guarded flow (or was tampered with after), you want to know immediately — not just see a lower score.

`require_hash: false` (default) — hash contributes 30 pts to the score but missing it doesn't block.

Both `require_hash` and `min_score` can be active at the same time and are enforced independently:

```json
{ "trust": { "require_hash": true, "min_score": 50 } }
```

A package with no hash → violation (hash_required).  
A package with hash but score 30/50 → violation (trust_score_too_low).  
A package with hash and score 65/50 → passes.

---

## The four factors

### Hash verified (30 pts)

Your lockfile already stores SHA-512 hashes of installed packages (`SyncWithTree`). If a package has a non-empty integrity entry, that's 30 points. No entry = 0 (or `hash_required` violation if enabled).

This rewards packages that were installed through SCAL-P's guarded flow. Manual installs or lockfile edits get 0.

### Version maturity (15 pts)

`major >= 1` → 15. Anything below 1.0.0 is pre-release. Zero-dependency parsing: split on ".", parse first component. `^0.5.0`, `~1.2.3`, `v2.0` all work.

### Weekly downloads (0–20 pts)

Thresholds are logarithmic:

| Downloads/week | Points |
|----------------|--------|
| < 100 | 0 |
| 100–999 | 5 |
| 1,000–9,999 | 10 |
| 10,000–99,999 | 15 |
| 100,000+ | 20 |

Fetched from `GET https://api.npmjs.org/downloads/point/last-week/{name}`. Cached in `.scalp/cache/trust.json` for 7 days.

Network failure with no cache → **10 pts** (unknown). Network failure with stale cache → uses stale cache.

HTTP call has a 10s timeout. If it fails, the scorer moves on — no blocking.

### No active CVEs (0 or 15 pts)

Runs `npm audit --json` once per evaluation, maps vulnerabilities by package **and version**.

**npm audit succeeded:**
- Package has open CVEs → 0 pts
- Package has no CVEs → 15 pts

**npm audit failed (pre-install, no lockfile, etc.):**
- Cache has a CVE entry for this specific version → 0 pts (previously confirmed bad)
- Cache has a clean entry for this version → 15 pts (previously confirmed clean)
- No cache for this version → **7 pts** (unknown)

---

## Cache

File: `.scalp/cache/trust.json` — auto-managed, never commit.

```json
{
  "lodash": {
    "fetched_at": "2026-05-13T12:00:00Z",
    "weekly_downloads": 142536,
    "versions": {
      "4.17.21": {
        "fetched_at": "2026-05-13T12:00:00Z",
        "cves": []
      },
      "4.17.20": {
        "fetched_at": "2026-05-10T12:00:00Z",
        "cves": ["GHSA-xxx"]
      }
    }
  }
}
```

Top-level keys are package names. `weekly_downloads` is per-package (same for all versions). `versions` maps exact version strings to per-version data (like CVEs, which can differ between versions).

TTL is 7 days from `fetched_at` for the top-level entry. Per-version entries have their own `fetched_at`.

The scorer loads the cache once at the start of `Evaluate()`, reads/writes entries during scoring, and saves at the end — but only if something changed (dirty flag).

---

## Violation messages

Trust violations include a breakdown so you know why:

```
trust_score: 17/50 (hash:0, maturity:0, dl:10, cves:7)
```

This tells you: no hash, no maturity, unknown downloads (10/20), unknown CVEs (7/15). One glance and you know the package is new and offline.

```
hash_required: package integrity not in lockfile
```

This tells you: `require_hash` is on and this package isn't tracked.

---

## Enforcement

Trust violations follow the same enforcement as policy violations:

- `"block"` → exits 1
- `"warn"` → logs and continues
- `"log"` → silent pass

There's no separate enforcement mode for trust. If you want trust to block but allowlist to warn, you can't — yet. Open an issue if that's a real use case.

---

## What it does NOT do (v0.2)

- No 2FA / verified email (npm doesn't expose this per-package)
- No Sigstore / provenance (v0.3)
- No typosquatting detection
- No persistent network daemon — every CLI call is stateless

---

## Code layout

```
internal/trust/
├── cache.go        — TrustCache: load, save, TTL, version-aware, concurrent-safe
├── cache_test.go
├── score.go        — Scorer: Evaluate(), 4 factor funcs, npm API client
└── score_test.go   — httptest-mocked API, no real network
```

`scorer.Evaluate()` is called from `cli/install.go`, `cli/audit.go`, and `cli/policy.go` — after the existing `policy.Evaluate()`. Violations are appended and enforced together.
