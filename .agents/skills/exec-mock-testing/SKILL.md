---
name: exec-mock-testing
description: Write tests that mock external commands (npm, pnpm, yarn, bun) using the SetExecCommand pattern. Use when writing tests for internal/npm/, internal/pnpm/, internal/yarn/, internal/bun/, or any code that calls exec.CommandContext.
---

## The pattern

Each adapter package has a package-level `execCommand` variable and a `SetExecCommand` function to swap it in tests:

```go
// production code
var execCommand = exec.CommandContext

func SetExecCommand(fn ExecFunc) ExecFunc {
    old := execCommand
    execCommand = fn
    return old
}
```

In tests, replace `execCommand` with a function that returns a fake `exec.Cmd`:

```go
func mockExec(t *testing.T, output string, exitCode int) {
    t.Helper()
    original := pnpm.SetExecCommand(func(ctx context.Context, name string, arg ...string) *exec.Cmd {
        cmd := exec.CommandContext(ctx, "echo", output)
        cmd.Stderr = os.Stderr
        return cmd
    })
    t.Cleanup(func() { pnpm.SetExecCommand(original) })
}
```

## What NOT to do

❌ Don't call `exec.Command` directly inside the mock function. Use `echo` or write to stdout manually.

❌ Don't write test assertions inside the mock function. Set up state before the call and assert after.

❌ Don't forget `t.Cleanup` to restore the original. If the mock leaks, other tests will break.

## Gotchas

- `cmd.Output()` returns `([]byte, error)`. The error is `*exec.ExitError` when exit code != 0. Tests must handle both paths — some commands (npm ls) exit 1 even on success (warnings).
- `cmd.Stderr` is forwarded to `os.Stderr` in production. In tests, you may need to capture it or discard it.
- `cmd.Stdin` is `os.Stdin` in production. In tests, use `strings.NewReader(input)`.
- The mock receives `name` and `arg...`. Assert on these in the mock to verify the right command is called.

## Example

```go
func TestGetTree(t *testing.T) {
    output := `[{"name":"root","version":"1.0","dependencies":{}}]`
    original := npm.SetExecCommand(func(ctx context.Context, name string, arg ...string) *exec.Cmd {
        cmd := exec.CommandContext(ctx, "echo", output)
        return cmd
    })
    t.Cleanup(func() { npm.SetExecCommand(original) })

    tree, err := npm.GetDependencyTree(context.Background())
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tree.Name != "root" {
        t.Errorf("expected root, got %s", tree.Name)
    }
}
```
