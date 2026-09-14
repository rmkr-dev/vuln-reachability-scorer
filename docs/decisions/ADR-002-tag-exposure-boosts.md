# ADR-002: Tag-based exposure boosts

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** @rmkr-dev
- **Related:** [ADR-001](ADR-001-scoring-model.md)

## Context

Criticality alone understates assets that carry regulated data or identity material. Operators already tag assets (`pii`, `identity`, …) in topology JSON; those tags should influence exposure without requiring a second criticality field.

## Decision

Extend exposure:

```text
exposure_factor = clamp(criticality + Σ tag_boosts[tag], 0, 1)
```

Ship defaults in `scoring.DEFAULT_TAG_BOOSTS` (`pii=0.15`, `identity=0.20`, `secrets=0.20`). Allow topology root `tag_boosts` to override/extend defaults (`loaders.load_tag_boosts`).

The core multiplicative formula from ADR-001 is unchanged.

## Alternatives considered

1. **Multiply criticality by a tag factor** — rejected; harder to reason about and easier to drive scores to near-zero accidentally.
2. **Separate “data sensitivity” axis in the product** — deferred; would be a fourth factor and need broader ADR churn.
3. **No defaults (operators must configure)** — rejected; empty boosts make tags inert and surprise users who already label assets.

## Consequences

- Changing default boosts is a behavior change (document in CHANGELOG / bump minor when defaults move).
- Overlapping tags can saturate exposure at 1.0 by design.
- Asset report and finding scores share the same exposure function.
