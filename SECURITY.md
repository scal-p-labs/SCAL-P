# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | (PoC — active development) |

## Reporting a Vulnerability

SCAL-P is a security tool — its own integrity matters as much as what it protects.

If you find a vulnerability in SCAL-P itself, **do not open a public issue**. Instead, report it privately:

- **GitHub**: use the private vulnerability reporting tool at  
  `https://github.com/carlsedujs/scal-p/security/advisories`

To help us triage efficiently, include:

- A clear description of the issue
- Steps to reproduce (code snippet, policy file, commands)
- Affected version(s)
- Potential impact (what an attacker could do)
- Suggested fix (if any)

We aim to acknowledge receipt within 48 hours and provide a timeline for a fix within 7 days.

## What SCAL-P considers a security issue

- Bypass of policy enforcement (install happens despite a `block` rule)
- Hash collision or hash mismatch that goes undetected
- Path traversal via package names (`../../etc`)
- Command injection via package manager arguments
- Audit log forgery or tampering
- TOCTOU (time-of-check/time-of-use) where a package passes pre-check but gets replaced during install

## What is NOT in scope

- Vulnerabilities in third-party packages installed via npm (use `npm audit` or Snyk for that)
- Lack of signature verification (planned for v0.2+)

## Disclosure Process

1. Report received → triage within 48h
2. Fix developed → tested on internal fork
3. Fix released → advisory published on GitHub + release notes
4. CVE assigned (if applicable)

## Severity Guidelines

- **Critical**: Remote code execution, policy bypass allowing malicious installs
- **High**: Integrity verification bypass, command injection
- **Medium**: Audit inconsistencies, partial enforcement issues
- **Low**: Logging issues, minor edge cases without exploitation path

## Security assumptions

SCAL-P assumes:

- The package manager (`npm`) may execute arbitrary code during install
- Package registries may serve compromised artifacts
- Maintainer accounts and CI pipelines may be compromised

SCAL-P does **not** assume:

- Trust in package authors
- Trust in registry integrity
- Trust in CI environments

## Build integrity

All releases are built with `goreleaser` and signed with `cosign`.  
Checksums are published alongside each release.

To verify with cosign:

```bash
cosign verify-blob \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt
```

To verify a binary:

```bash
goreleaser verify --dist dist/ checksums.txt
```

Or use the built-in checksum file:

```bash
sha256sum -c checksums.txt
```
