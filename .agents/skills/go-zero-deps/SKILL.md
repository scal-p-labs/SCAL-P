---
name: go-zero-deps
description: Write Go code using only the Go standard library in this project. Every import must be justified. Activate when writing Go files, adding imports, or suggesting dependencies. This is a hard constraint — no exceptions.
---

## Hard rule: stdlib only

Every import must be from the Go standard library. If you're about to add an import that isn't in the stdlib, stop and find a stdlib alternative.

## What IS in stdlib (that you might not know)

| You might reach for... | Use stdlib instead |
|------------------------|-------------------|
| `gopkg.in/yaml.v3` | `encoding/json` + `bufio.Scanner` for pnpm-lock.yaml |
| `godotenv` | `os.Getenv` |
| `testify/assert` | Raw `testing.T` methods |
| `logrus` / `zerolog` | `log/slog` |
| `samber/lo` | `slices`, `maps`, `cmp` (all stdlib since Go 1.21-1.22) |
| `hashicorp/multierror` | `errors.Join` |
| `rs/cors` | `net/http` middleware (write it yourself) |
| `spf13/cobra` | `flag` package with `flag.FlagSet` (already in use) |
| `spf13/viper` | Hardcoded config structs + JSON `encoding/json` (already in use) |

## Gotchas

- `strings.TrimSpace` exists in stdlib. Don't import external string utils.
- `slog.Handler` is an interface in `log/slog`. You can implement custom handlers (see `internal/cli/handler.go`).
- `testing` package has `t.TempDir()`, `t.Helper()`, `t.Cleanup()`. No need for external test helpers.
- `net/http/httptest` has `httptest.NewServer` and `httptest.NewRecorder` for HTTP mocking.
