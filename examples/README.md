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

Prefer checked-in configs over long flag chains ([ADR-006](../docs/decisions/ADR-006-config-file.md)):

| File | Intent |
| --- | --- |
| `vrscore-base.toml` | Shared `topology` / `findings` paths for `extends` |
| `vrscore.toml` | Table defaults for the sample estate |
| `vrscore.json` | JSON + band + reachable filters |
| `vrscore-triage.toml` | Explain + hop window + high/critical bands + dedupe |
| `vrscore-ci.toml` | Quiet SARIF export + `fail_under` for Actions |
| `vrscore-multi.toml` | Merge `findings.json` + `findings-extra.json` with dedupe |
| `vrscore-exclude.toml` | Drop `batch-worker` + `dmz`-tagged assets via config excludes |

```bash
vrscore --config examples/vrscore.toml
vrscore -c examples/vrscore.json
vrscore -c examples/vrscore-triage.toml
vrscore -c examples/vrscore-ci.toml
vrscore -c examples/vrscore-multi.toml
vrscore -c examples/vrscore-exclude.toml
# Override one knob without re-listing filters:
vrscore -c examples/vrscore-triage.toml --format json --limit 10
```

See the [usage cookbook](../docs/usage/README.md#config-first-triage) for recipes.
