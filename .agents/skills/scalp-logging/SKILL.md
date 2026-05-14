---
name: scalp-logging
description: Use log/slog for observability in this project. Use when adding log messages, debugging output, or user-facing status messages.
---

## Two output modes

This project has a custom `slog.Handler` that switches behavior based on `--debug`:

| `--debug` | slog.Warn shows | slog.Info shows | slog.Debug shows |
|-----------|----------------|----------------|-----------------|
| absent | `! message` | `message` | hidden |
| present | `time=... level=WARN msg=...` | `time=... level=INFO msg=...` | `time=... level=DEBUG msg=...` |

## When to use each level

| Level | When | Example |
|-------|------|---------|
| `slog.Debug` | Details only useful for debugging | package path fallback, cache TTL check |
| `slog.Info` | Normal operation events | "audit ok", "binary verified" |
| `slog.Warn` | Something is wrong but not blocking | policy not found, trust score error |
| No slog | User-facing output that's always shown | violation details, checksums output |

## For always-visible output

If a message MUST be seen regardless of `--debug`, use `fmt.Fprintln(os.Stderr, msg)`.

But most things should go through slog. The project's convention is: if it's useful for debugging → slog.Debug. If the user should see it in normal operation → slog.Info.

## Gotchas

- `slog.Debug` messages are SILENT without `--debug`. Don't put important info at Debug level.
- The custom handler in `internal/cli/handler.go` does NOT display slog attributes by default. Key=value pairs only show in `--debug` mode. The exception is `slog.Warn("...", "details", multilineString)` which prints the details.
- `slog.Error` is not used in this codebase. Return errors normally.
- Don't call `slog.SetDefault` outside of `main.go`. It's a global and affects all packages.
