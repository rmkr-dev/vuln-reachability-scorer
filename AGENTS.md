# Agent and human guardrails

Read this file before you change this repository. These rules apply to people and to coding agents.

## Before you write code

1. Read `README.md`, this file, and the docs that touch your change (`docs/architecture/`, `docs/decisions/`, `docs/development/`, `docs/security/`).
2. State the slice you are completing. If the work is larger than one reviewable PR, split it.
3. Prefer the smallest change that is **correct and complete** for that slice. Do not “while you’re here” refactor.

## Human-first

- Write for a reviewer who was not in the session: commit messages, PR body, and docs must stand alone.
- Do not leave the human to reverse-engineer intent from a dump of files.
- High-impact changes (license, security defaults, CI required checks, public API, scoring formula) need **human approval** before merge. An agent may draft; a person decides.

## Complete across layers

A slice is not done if you updated only one layer. When the change needs them, update together:

- behavior (code)
- tests
- CI / repo automation
- docs that describe the behavior
- architecture or an ADR, if the shape of the system or the scoring model changed

Do not add a file that nothing references, or a doc that describes a file that does not exist.

## No orphans, no speculation, no fakes

- **No orphans:** every new doc, script, or workflow has a reader and a reason.
- **No speculative engineering:** do not add frameworks, dashboards, or “future-proof” abstractions for slices that are not in scope.
- **No fake implementations:** no stub scorers that pretend to work, no badges for CI that is not running, no architecture diagrams of systems that are not in this repo.
- **Docs match reality.** If a feature is planned, say it is planned.

## Scope of this project

- **In scope:** offline Python CLI that loads topology + findings JSON and emits reachability-aware priority scores.
- **Out of scope:** live scanner integrations, cloud APIs, Node/npm, secrets, company-specific branding.

## Tests and CI

- When application code exists, tests ship in the same PR as the behavior.
- Prefer GitHub Actions and the reusable Python CI workflow from `rmkr-dev/gha-reusable-workflows` when CI is added.
- GitHub Free-first: no paid features required for a green default pipeline.

## Security by default

- No secrets in the repo, in examples, or in commit messages.
- Least privilege for tokens and workflow permissions.
- Report vulnerabilities per `SECURITY.md` when that file exists.

## Definition of done

- [ ] Scope matches the agreed slice; nothing extra landed “for later convenience”
- [ ] Behavior, tests, automation, and docs that this slice requires are present and consistent
- [ ] No secrets, personal contact details, or leftover placeholders that claim to be finished
- [ ] `README.md` and any linked docs still describe the repo as it is
- [ ] Significant decisions have an ADR
- [ ] You could merge this PR and leave the repo coherent if no further PR ever shipped

## Final self-review

1. Diff the PR as a stranger. Is anything unexplained?
2. Grep for names of files you added. Are they linked from `README.md` or the right `docs/` index?
3. Confirm you did **not** add Node/npm.
4. Confirm commit messages are conventional (`feat:`, `docs:`, `ci:`, `chore:`, …) and read like a person wrote them.
5. Re-read this file and fix anything that now contradicts reality.
