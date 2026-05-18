# E2E fixtures

Fixtures live under `testdata/` and are copied into temp dirs for E2E runs.
They are minimal, deterministic projects for npm/pnpm/yarn/bun scenarios.

Structure:

```
testdata/
  npm/
  pnpm/
  yarn/
  bun/
  golden/
```

Each scenario folder contains:

- `package.json` (and workspace manifests where needed)
- the package manager lockfile
- `.scalp/policy.json` if the scenario requires a policy

Keep fixtures small and auditable.
