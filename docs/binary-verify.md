# Binary verify — dogfooding your own tool

**RFC v0.2 — SCAL-P verifies SCAL-P**

> SCAL-P spends all day verifying npm packages. But what about SCAL-P itself? Binary verify closes the loop: the same hashing and policy engine that protects your dependencies also protects your SCAL-P binary.

---

## What it is

Two commands that form a release verification chain:

**`scalp checksum`** — generate a checksums file for release artifacts:

```bash
scalp checksum scalp_linux_amd64.tar.gz scalp_darwin_amd64.tar.gz > checksums.txt
```

Output:
```
sha512-a1b2c3d4...  scalp_linux_amd64.tar.gz
sha512-e5f6g7h8...  scalp_darwin_amd64.tar.gz
```

**`scalp verify`** — verify a downloaded artifact against the checksums file:

```bash
scalp verify \
  --artifact scalp_linux_amd64.tar.gz \
  --checksum checksums.txt \
  --policy .scalp/policy.json
```

Exit 0 if hash matches, enforcement action if it doesn't.

---

## Why dogfooding matters

SCAL-P's entire value proposition is "verify before trust." If you can't verify the tool that does the verifying, you have a trust problem.

The release pipeline generates checksums with `scalp checksum`. You download the binary and the checksums file (ideally over HTTPS or signed). You run `scalp verify`. It computes SHA-512 of the binary, compares against the expected hash, logs to `.scalp/audit.log`, and enforces the result.

Same hash format (`sha512-<base64>`). Same audit logging. Same policy enforcement. No special cases for SCAL-P itself.

---

## Commands

### `scalp checksum`

```
scalp checksum [--output <file>] <files...>
```

Reads each file, computes SHA-512, writes one line per file in `sha512-<hash>  <filename>` format.

- `--output` writes to file instead of stdout
- Without `--output`, pipe it: `scalp checksum *.tar.gz > checksums.txt`

No policy, no audit, no enforcement. It's just a hash tool.

### `scalp verify`

```
scalp verify --artifact <file> --checksum <file> [--policy <file>] [--ci]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--artifact` | required | path to the downloaded release artifact |
| `--checksum` | required | path to the checksums file |
| `--policy` | `.scalp/policy.json` | policy controlling enforcement |
| `--ci` | false | override enforcement to block |

Flow:

1. Loads policy (or defaults)
2. Parses checksums file (skips blank lines and `#` comments)
3. Looks up artifact filename in checksums
4. Computes SHA-512 of the artifact
5. Compares hashes
6. Logs a `binary_verify` audit event with status and hash match
7. If mismatch, applies enforcement from policy: `warn` (default), `block`, or `log`

### Enforcement

Default is `warn` — mismatch is logged but exit 0. You decide the criticality.

| Enforcement | Hash match | Hash mismatch |
|-------------|-----------|---------------|
| `warn` (default) | exit 0 | logged, exit 0 |
| `block` | exit 0 | exit 1 |
| `log` | exit 0 | silent, exit 0 |

With `--ci`, enforcement is forced to `block` regardless of policy.

---

## Audit events

Every `scalp verify` call produces one audit event:

```
{"ts":"2026-05-13T12:00:00Z","event":"binary_verify","pkg":"scalp_linux_amd64.tar.gz","status":"verified","hash_match":true}
```

Status is `"verified"` on match, `"mismatch"` on failure. The event is appended to `.scalp/audit.log` alongside all other SCAL-P events.

---

## Example: release pipeline

```yaml
# Generate checksums during release
- run: scalp checksum scalp_*.tar.gz > checksums.txt

# Upload both
- run: |
    gh release create v0.2.0 \
      scalp_linux_amd64.tar.gz \
      scalp_darwin_amd64.tar.gz \
      checksums.txt
```

```yaml
# User verifies after download
- run: |
    scalp verify \
      --artifact scalp_linux_amd64.tar.gz \
      --checksum checksums.txt \
      --ci
```

---

## What it does NOT do

- Does not GPG-sign the checksums file (do that separately)
- Does not verify checksums file authenticity (HTTPS + signing is on you)
- Does not scan the binary for malware (that's your OS vendor's job)
- Does not support wildcards in `--artifact` (one file at a time)

---

## Code layout

```
internal/hash/
├── file.go       — hash.File(): SHA-512 single file, same format as Dir()
└── file_test.go

internal/cli/
├── checksum.go   — runChecksum(): generate checksums file
└── verify.go     — runVerify(): verify artifact, compare, audit, enforce
```
