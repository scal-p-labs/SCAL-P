# Getting started

**From zero to a guarded install in about 2 minutes.**

> You have a JavaScript project with a `package.json`. You want to know what you're installing before you install it.

---

## 1. Install scalp

Download the latest binary from [releases](https://github.com/CarlosEduJs/SCAL-P/releases):

```bash
# Linux
curl -L https://github.com/CarlosEduJs/SCAL-P/releases/latest/download/scalp_linux_amd64.tar.gz | tar xz
sudo mv scalp /usr/local/bin/

# macOS
curl -L https://github.com/CarlosEduJs/SCAL-P/releases/latest/download/scalp_darwin_amd64.tar.gz | tar xz
sudo mv scalp /usr/local/bin/
```

Or build from source:

```bash
git clone https://github.com/CarlosEduJs/SCAL-P
cd SCAL-P
make build
# binary at .bin/scal-p
```

---

## 2. Run your first CI check

Go to your project directory and run:

```bash
cd my-project
scalp ci
```

That's it. No config, no setup. `scalp ci` does everything: resolves dependencies, evaluates against default policy (allow + warn + audit), installs, hashes every installed package, and saves a report to `.scalp/ci-report.json`.

If this is your first time, you'll see something like:

```
WARN policy not found; allowing with audit
INFO binary verified artifact=lodash…
INFO binary verified artifact=express…
INFO ci passed: 0 violations
```

All packages passed because the default policy only audits. No blocking.

---

## 3. Check the report

```json
{
  "version": "0.2",
  "passed": true,
  "audit": {
    "verified": 142,
    "mismatched": 0,
    "missing": 0
  }
}
```

142 packages hashed and verified. All match. Your `node_modules` is consistent with what was installed.

---

## 4. Set up a policy

Create `.scalp/policy.json`:

```json
{
  "version": 1,
  "trust": { "min_score": 60 },
  "enforcement": { "on_violation": "warn" }
}
```

Run `scalp ci` again. Now every package is scored. Any package below 60 gets reported. The default enforcement (`warn`) means you see them without blocking.

When you're ready to block:

```json
{ "enforcement": { "on_violation": "block" } }
```

Now `scalp ci` exits 1 on violations — suitable for CI pipelines.

---

## 5. What to do next

| If you want to... | Go here |
|-------------------|---------|
| Understand trust scores | `docs/trust-score.md` |
| Set up CI in GitHub Actions | `docs/scalp-ci.md` |
| Verify SCAL-P's own binary | `docs/binary-verify.md` |
| See every policy option | `docs/policy.md` |
| Edit policy with autocomplete | Open `.scalp/policy.json` — `$schema` points to `.scalp/policy.schema.json` |

---

## Directory structure after first run

```
my-project/
├── .scalp/
│   ├── policy.json          ← your policy (create this)
│   ├── policy.schema.json   ← JSON Schema for autocomplete
│   ├── lockfile.json        ← auto-generated: SHA-512 hashes of packages
│   ├── ci-report.json       ← CI report from last run
│   ├── cache/
│   │   └── trust.json       ← cached download counts and CVEs
│   └── audit.log            ← every event, append-only
├── node_modules/
├── package.json
├── package-lock.json    (npm)
├── pnpm-lock.yaml       (pnpm)
├── yarn.lock            (yarn)
└── bun.lock             (bun)
```
