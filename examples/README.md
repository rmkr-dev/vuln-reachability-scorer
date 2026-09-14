# Example inputs

Synthetic topology and findings for local demos. Asset names are fictional; CVE identifiers are real public records used only as severity illustrations.

```bash
vrscore --topology examples/topology.json --findings examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --format json
vrscore -t examples/topology.json -f examples/findings.json --format sarif
vrscore -t examples/topology.json -f examples/findings.json --format html -o report.html
vrscore -t examples/topology.json -f examples/findings.json --format markdown -o report.md
```

Expected shape: ingress (`edge-lb`) findings and high-criticality near-ingress assets rank above equally severe findings on isolated or deep assets.


## Triage filter demos

```bash
vrscore -t examples/topology.json -f examples/findings.json --only-reachable --summary
vrscore -t examples/topology.json -f examples/findings.json --max-hops 1 --explain
vrscore -t examples/topology.json -f examples/findings.json --band high --band critical
vrscore -t examples/topology.json -f examples/findings.json --tag pii --tag identity
vrscore -t examples/topology.json -f examples/findings.json --dedupe --cve CVE-2021-44228
vrscore -t examples/topology.json -f examples/findings.json --min-base 7 --sort hops
vrscore -t examples/topology.json -f examples/findings.json --format tsv -o /tmp/scores.tsv
vrscore -t examples/topology.json -f examples/findings.json --format junit -o /tmp/scores.xml
```

## Config samples

- `vrscore.toml` — table defaults for the sample estate
- `vrscore.json` — JSON format with band + reachable filters

```bash
vrscore --config examples/vrscore.toml
vrscore -c examples/vrscore.json
```

See the [usage cookbook triage playbook](../docs/usage/README.md#triage-playbook-sample-estate) for a full recipe chain.
