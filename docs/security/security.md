# Security posture

## Threat model (this repo)

This project is an **offline CLI**. It reads local JSON files and writes scores to stdout or files the operator chooses. It does not open network sockets as part of scoring, and it must not embed credentials.

## Rules

- No secrets, tokens, or private keys in the repository, examples, or commit messages.
- Example topology and findings use fictional asset names and public CVE identifiers only.
- Workflows (when added) run with least-privilege `permissions`.
- Dependency updates prefer Dependabot on GitHub Actions and Python packages when those files exist.

## Reporting

When `SECURITY.md` exists at the repo root, follow that process. Until then, use GitHub Security Advisories on this repository (private draft) and avoid public issues for exploitable defects.
