# ADR-001: Reachability × exposure scoring model

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** @rmkr-dev

## Context

Raw CVSS (or scanner “severity”) ranks every finding as if exposure were equal. In a real estate, an internet-facing load balancer and an isolated batch worker with the same CVSS are not equally urgent. We need a **transparent, offline** formula that operators can audit and tune without training a model or calling a SaaS API.

## Decision

Use a multiplicative priority:

```text
priority_score = round(base_score × reachability_factor × exposure_factor, 2)
```

Where:

- `base_score` ∈ `[0, 10]` — supplied on each finding (typically CVSS base).
- `reachability_factor` ∈ `{1.0, 0.8, 0.55, 0.35, 0.2, 0.1}` — from shortest directed hop distance to an ingress asset (`asset.ingress` or target of an `internet_facing` edge). Unreachable / no ingress → `0.1`.
- `exposure_factor` ∈ `[0, 1]` — the asset’s `criticality` from topology.

Implementation: `src/vuln_reachability_scorer/scoring.py` and `graph.py`.

## Alternatives considered

1. **CVSS-only ranking** — rejected; ignores topology, which is the purpose of this tool.
2. **Additive score** (`base + bonus`) — rejected; harder to keep on a comparable `[0, 10]` scale and easier to overweight bonuses.
3. **Learned / ML ranker** — rejected for v0.1; opaque, needs labeled data, conflicts with “docs match reality” and offline CLI goals.
4. **Full attack-path enumeration (all paths, exploitability graphs)** — deferred; hop distance is enough for v0.1 and stays explainable.

## Consequences

- Operators must supply topology criticality and ingress honestly; garbage topology yields garbage priorities.
- Same CVE on two assets can (and should) receive different priorities.
- Factor tables are part of the public contract; changing them is a semver-minor (behavior) change and should update this ADR or a follow-up ADR.
- Not a replacement for CVSS — it **reweights** CVSS using local topology.

## References

- Module docstring in `scoring.py`
- [docs/architecture/architecture.md](../architecture/architecture.md)
