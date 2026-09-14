# Usage cookbook

Practical recipes for `vrscore`. All commands assume an editable install (`pip install -e ".[dev]"`).

## Score the sample estate

```bash
vrscore -t examples/topology.json -f examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --explain
```

## Validate topology before findings arrive

```bash
vrscore -t examples/topology.json --asset-report
vrscore -t examples/topology.json --asset-report --format json -o assets.json
```

## Export for spreadsheets or code scanning

```bash
vrscore -t examples/topology.json -f examples/findings.json --format csv -o scores.csv
vrscore -t examples/topology.json -f examples/findings.json --format sarif -o scores.sarif
```

## Focus triage

```bash
vrscore -t examples/topology.json -f examples/findings.json --min-priority 4 --limit 10 --explain
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
