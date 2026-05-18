---
name: adapter-pattern
description: Implement or modify a PackageManager adapter (npm, pnpm, or a new one). Use when adding support for a new package manager, modifying the PackageManager interface, or working with internal/pkgmanager/.
---

## The interface

Every adapter implements `pkgmanager.PackageManager`:

```go
type PackageManager interface {
    Name() string
    Resolve(ctx context.Context, args ...string) error
    ParseLockfile(ctx context.Context) ([]PackageNode, error)
    Install(ctx context.Context, args ...string) error
    GetTree(ctx context.Context) (DependencyTree, error)
    LocalPath(name string) string
}
```

## What each method does

| Method | When called | What it should do |
|--------|-------------|-------------------|
| `Resolve` | Before policy evaluation | Run a lockfile-only install (no `node_modules`). Use `--ignore-scripts` to prevent lifecycle scripts. |
| `ParseLockfile` | After Resolve, before Install | Read the lockfile (e.g., `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`) and return all packages as a flat list. Must work **without** `node_modules` installed. |
| `Install` | After policy passes | Run the actual install. Passthrough `os.Stdin`, `os.Stdout`, `os.Stderr`. |
| `GetTree` | After Install | Return the full dependency tree. Used for hash sync and audit. |
| `LocalPath` | Any time | Return the filesystem path for a package directory. Usually `"node_modules/" + name`. |

## Registration pattern

Each adapter registers itself in a `Register()` function called from `cli.init()`:

```go
func Register() {
    pkgmanager.Register("pnpm", func() pkgmanager.PackageManager {
        return &Adapter{}
    })
}
```

The registry uses `sync.RWMutex` for concurrent access. Registration happens before any `Get` call.

## Exec mocking

Each adapter MUST expose `SetExecCommand` for testing:

```go
var execCommand = exec.CommandContext

type ExecFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd

func SetExecCommand(fn ExecFunc) ExecFunc {
    old := execCommand
    execCommand = fn
    return old
}
```

Any production code that runs external commands must use `execCommand`, not `exec.CommandContext` directly.

## Gotchas

- `npm ls --all --json` exits 1 for peer dep warnings but still outputs valid JSON. Use `errors.As(err, &exitErr)` and check for empty stdout before failing.
- `pnpm-lock.yaml` and `yarn.lock` (Berry) are YAML-like but we parse them with a custom line-by-line scanner (no external YAML dep). See `internal/pnpm/adapter.go`, `internal/yarn/lockfile.go`.
- `bun.lock` (Bun 1.1+ text format) also uses a custom line-by-line scanner. See `internal/bun/lockfile.go`.
- Lockfile parsers must handle optional platform-specific packages (e.g., `lightningcss-android-arm64`). These are NOT installed on the current platform.
- `ParseLockfile` is called PRE-install. It must work without `node_modules`.
- `GetTree` is called POST-install. It can use `ls` commands that need `node_modules`.
