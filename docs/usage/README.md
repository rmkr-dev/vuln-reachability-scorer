# Usage cookbook

Practical recipes for `vrscore`. All commands assume an editable install (`pip install -e ".[dev]"`).

## Score the sample estate

```bash
vrscore -t examples/topology.json -f examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --explain
# explain lines include ingress -> asset path when reachable
```

## Validate topology before findings arrive

```bash
vrscore -t examples/topology.json --asset-report
vrscore -t examples/topology.json --asset-report --format json -o assets.json
vrscore -t examples/topology.json --asset-report --format csv -o assets.csv
```

## Export for spreadsheets or code scanning

```bash
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o scores.sarif
```

## Focus triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4 --limit 10 --explain
vrscore -t examples/topology.json -f examples/findings.json --summary
```

## Raise exposure for sensitive tags

Ship `tag_boosts` in topology (merged over defaults `pii` / `identity` / `secrets`):

```json
{
  "tag_boosts": {"pii": 0.25, "pci": 0.2},
  "assets": [{"id": "db", "criticality": 0.6, "tags": ["pii", "pci"], "ingress": false}],
  "edges": []
}
```

Effective exposure is `clamp(criticality + Σ boosts, 0, 1)`.

## Strict topology hygiene

```bash
vrscore -t topology.json -f findings.json --strict
```

Fails (exit 2) if any edge references an unknown asset id.

## Mark Known Exploited findings

Set `"kev": true` on a finding to apply the 1.15 KEV multiplier (see [ADR-003](../decisions/ADR-003-kev-multiplier.md)).

## CI gate

```bash
vrscore -t topology.json -f findings.json --fail-under 7 --summary
```

Exits `1` if any scored finding has `priority_score >= 7`, suitable as a required check.
