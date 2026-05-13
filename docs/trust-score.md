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
| Weekly downloads | 20 | `api.npmjs.org` | degraded (cached) |
| No active CVEs | 15 | `npm audit --json` | degraded (cached) |

If the score is below `trust.min_score` in your policy, it's a violation — same as a denied package.

```json
{
  "trust": {
    "mode": "allowlist",
    "min_score": 60
  }
}
```

`min_score: 0` (default) means trust scoring is disabled. No behavior change from v0.1.

---

## The four factors

### Hash verified (30 pts)

Your lockfile already stores SHA-512 hashes of installed packages (`SyncWithTree`). If a package has a non-empty integrity entry, that's 30 points. No entry = 0.

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

Fetched from `GET https://api.npmjs.org/downloads/point/last-week/{name}`. Cached in `.scalp/cache/trust.json` for 7 days. Cache miss + network failure = degraded score (no points, keeps using stale cache if available).

HTTP call has a 10s timeout. If it fails, the scorer moves on — no blocking.

### No active CVEs (15 pts)

Runs `npm audit --json` once per evaluation, maps vulnerabilities by package name. If the audit says your package has open CVEs, you get 0. If clean, 15.

In guarded mode (pre-install), there's no node_modules to audit — so this factor uses whatever is in cache, or gets 0. The other three factors still contribute normally.

---

## Cache

File: `.scalp/cache/trust.json` — auto-managed, never commit.

```json
{
  "lodash": {
    "fetched_at": "2026-05-13T12:00:00Z",
    "weekly_downloads": 142536,
    "cves": []
  }
}
```

Keys are package names (no version — download counts and CVEs are per-name). TTL is 7 days from `fetched_at`.

The scorer loads the cache once at the start of `Evaluate()`, reads/writes entries during scoring, and saves at the end — but only if something changed (dirty flag).

---

## What it does NOT do (v0.2)

- No 2FA / verified email (npm doesn't expose this per-package)
- No Sigstore / provenance (v0.3)
- No typosquatting detection
- No per-version download tracking (it's per-package)
- No persistent network daemon — every CLI call is stateless

If you need higher granularity, `min_score: 60` with the current factors means a package needs hash + maturity + decent downloads or CVEs to pass. 60 from 80 available is a reasonable bar.

---

## Enforcement

Trust violations follow the same enforcement as policy violations:

- `"block"` → exits 1
- `"warn"` → logs and continues
- `"log"` → silent pass

There's no separate enforcement mode for trust. If you want trust to block but allowlist to warn, you can't — yet. Open an issue if that's a real use case.

---

## Code layout

```
internal/trust/
├── cache.go        — TrustCache: load, save, TTL, concurrent-safe
├── cache_test.go
├── score.go        — Scorer: Evaluate(), 4 factor funcs, npm API client
└── score_test.go   — httptest-mocked API, no real network
```

`scorer.Evaluate()` is called from `cli/install.go`, `cli/audit.go`, and `cli/policy.go` — after the existing `policy.Evaluate()`. Violations are appended and enforced together.
