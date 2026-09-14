# Security policy

## Supported versions

Security fixes apply to the default branch (`main`) and to the latest released tag when releases exist.

| Version | Supported |
| --- | --- |
| main | yes |
| 0.2.x | yes |
| < 0.2 | no |

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories for this repository:

1. Open **Security** → **Advisories** → **New draft security advisory** on `rmkr-dev/vuln-reachability-scorer`, or
2. Use **Report a vulnerability** if that button is enabled on the repo’s Security tab.

Do **not** open a public issue for vulnerabilities that could lead to unsafe defaults or secret exposure in examples/workflows.

Include:

- A short description of the issue and impact
- Steps to reproduce
- Any suggested fix

You should receive an acknowledgment within a reasonable time. Coordinated disclosure is preferred.

## Scope notes

- Do not send secrets, tokens, or personal data in reports.
- Contact is GitHub-only via `@rmkr-dev` / this repository’s advisory flow — no email addresses are published here.
- This CLI is offline; reports about third-party scanners or CVE databases are out of scope unless they affect code in this repository.
