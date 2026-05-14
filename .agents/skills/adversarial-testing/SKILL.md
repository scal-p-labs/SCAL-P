---
name: adversarial-testing
description: Write adversarial tests that simulate attacks against the security tool. Use when writing tests for security-critical code paths, lockfile verification, trust scoring, or the audit system.
---

## What to test

Adversarial tests validate that SCAL-P detects attacks. Each test should:
1. Set up a scenario (attacker has modified something)
2. Run the verification function
3. Assert the correct violation is produced

## Common adversarial scenarios

| Scenario | What it simulates | Expected result |
|----------|------------------|-----------------|
| Lockfile hash != real content | Attacker modified the lockfile after sync | `hash_mismatch` violation |
| File modified after sync | Attacker injected code into installed package | `hash_mismatch` violation |
| Package directory deleted | Attacker removed evidence | `package_not_installed` violation |
| Lockfile has wrong hash | Attacker tampered with lockfile metadata | `hash_mismatch` violation |
| Package not in lockfile, on disk | Package installed outside guarded mode | `missing_lock_entry` violation |
| Optional platform dep in tree, not on disk | Cross-platform dep, not a real attack | SKIP (no violation) |
| Stale cache with future timestamp | Cache poisoning | `IsExpired` returns false |
| Corrupted cache JSON | Attack via malformed data | LoadCache returns error, no panic |

## Structure

```go
func TestAdversarial_scenarioName(t *testing.T) {
    dir := t.TempDir()
    old := chdir(t, dir)
    defer restoreWd(t, old)

    // 1. Set up the attack
    pkgDir := filepath.Join("node_modules", "target")
    os.MkdirAll(pkgDir, 0o755)
    os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte("compromised"), 0o644)

    tree := pkgmanager.DependencyTree{...}
    lf := newLockfile("")
    lf.Packages["target@1.0"] = newEntry("url", "sha512-validhash", "past")

    // 2. Run verification
    violations, events, err := lockfile.VerifyAgainstTree(ctx, &lf, tree, pm)

    // 3. Assert detection
    if len(violations) == 0 {
        t.Fatal("expected violation, got none")
    }
    if violations[0].Reason != "hash_mismatch" {
        t.Errorf("expected hash_mismatch, got %s", violations[0].Reason)
    }
}
```

## Where to add tests

Put adversarial tests in the relevant package's `_test.go` file, grouped under a `TestAdversarial_` prefix:

- Lockfile scenarios → `internal/lockfile/sync_test.go`
- Trust score scenarios → `internal/trust/score_test.go`
- Cache poisoning → `internal/trust/cache_test.go`
- CLI behavior → `internal/cli/verify_test.go`

## Gotchas

- Tests must use `t.TempDir()` for isolation. Never write to real project directories.
- Use the `chdir(t, dir) / restoreWd(t, old)` pattern for filesystem-dependent tests.
- Mock ALL external commands using `SetExecCommand`. The test shouldn't call real npm/pnpm.
- For trust score tests, use `SetAuditFunc` to mock npm audit data instead of calling real `npm audit --json`.
- Use `httptest.NewServer` to mock the npm registry API for download counts.
- Tree structures use `pkgmanager.DependencyTree` and `DependencyRef`. Build them inline in the test.
