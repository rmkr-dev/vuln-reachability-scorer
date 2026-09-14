# ADR-004: Optional EPSS input factor

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** @rmkr-dev
- **Related:** [ADR-001](ADR-001-scoring-model.md), [ADR-003](ADR-003-kev-multiplier.md)

## Context

[FIRST EPSS](https://www.first.org/epss/) is a 0–1 probability that a CVE will be exploited in the wild in the next 30 days. Scanner exports often already include it. The CLI is offline, so it should accept an optional per-finding `epss` value rather than fetching scores at runtime.

## Decision

- Add optional `Finding.epss: float | None` in `[0, 1]`. Omitted / JSON `null` means no EPSS adjustment.
- When present, after the ADR-001 product and the ADR-003 KEV multiplier:

  ```text
  epss_factor = 1.0 + EPSS_WEIGHT × epss    # EPSS_WEIGHT = 0.20
  priority = min(10.0, round(priority × epss_factor, 2))
  ```

- Record a note on the scored finding. JSON/CSV/`--explain` surface the input.
- Do **not** call FIRST (or any network) from this CLI.

`epss: 0.0` is a no-op on the numeric score (factor 1.00) but still records that EPSS was supplied. Omitting the field is the quiet default for inputs that have no EPSS.

## Alternatives considered

1. **Fetch EPSS from FIRST at runtime** — rejected; breaks the offline guarantee (same reason KEV is not fetched).
2. **Replace `base_score` with an EPSS-blended severity** — rejected; loses CVSS information operators already trust.
3. **Fourth multiplicative axis always present** (treat missing as 0.5) — rejected; would silently down-rank every finding without EPSS.
4. **Additive bonus** — rejected; harder to keep on the `[0, 10]` scale and inconsistent with KEV.

## Consequences

- Changing `EPSS_WEIGHT` is a behavior change (CHANGELOG + consider a minor bump).
- Operators are responsible for accurate `epss` values.
- KEV and EPSS can both apply; KEV runs first, then EPSS, each clamped at 10.0.
- Live EPSS sync would need a future ADR and an explicit opt-in network mode.

## References

- [FIRST EPSS](https://www.first.org/epss/)
- Module docstring in `scoring.py`
