# ADR-003: Known Exploited Vulnerability (KEV) multiplier

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** @rmkr-dev
- **Related:** [ADR-001](ADR-001-scoring-model.md)

## Context

CISA KEV membership is a strong exploitation signal that CVSS and topology alone miss. Operators often already know which findings are on the KEV list; the CLI should accept that boolean without calling the network.

## Decision

- Add optional `Finding.kev: bool` (default false).
- When true: `priority = min(10.0, round(priority * KEV_FACTOR, 2))` with `KEV_FACTOR = 1.15`.
- Record a note on the scored finding.
- Do **not** fetch the KEV catalog at runtime in v0.1.x.

## Alternatives considered

1. **Fetch CISA KEV JSON in the CLI** — rejected for v0.1; breaks offline guarantee.
2. **Additive KEV bonus** — rejected; multiplicative nudge keeps scale comparable and matches how teams verbally “weight” KEV.
3. **Replace base_score when KEV** — rejected; loses CVSS information.

## Consequences

- Changing `KEV_FACTOR` is a behavior change (CHANGELOG + consider minor bump).
- Operators are responsible for accurate `kev` flags.
- Live KEV sync would need a future ADR and an explicit opt-in network mode.
