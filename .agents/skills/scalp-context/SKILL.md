---
name: scalp-context
description: Propagate context.Context correctly through all I/O functions in this project. Use when writing functions that perform filesystem, network, or exec operations.
---

## Rules

1. `context.Context` is the **first argument** of every function that does I/O
2. Check context at function entry: `ctxutil.Check(ctx)`
3. Check context **inside loops** that do I/O per iteration

## Entry check

```go
func SyncWithTree(ctx context.Context, lf *Lockfile, ...) ([]audit.Event, error) {
    if err := ctxutil.Check(ctx); err != nil {
        return nil, err
    }
    // ...
}
```

## Loop check

```go
for _, node := range nodes {
    if err := ctxutil.Check(ctx); err != nil {
        return nil, err
    }
    // do I/O for this node
}
```

This pattern already exists in `internal/hash/dir.go` and `internal/lockfile/sync.go`. New code must follow the same.

## What NOT to do

❌ Don't store `context.Context` in a struct — pass it explicitly. The one exception is `http.Client` (which is a context carrier, not a context user).

❌ Don't use `context.Background()` inside library code. Only `main.go` and test files use it. Production code receives context from the caller.

## Gotchas

- `slog` calls do NOT need context. They use `context.Background()` internally.
- `hash.Dir` checks context inside the loop (line 48-51 in `dir.go`). This is the model for all new loops.
- Functions that are purely computational (no I/O) do NOT need context. E.g., `ScoreMaturity`, `parseVersion`, `Flatten`.
