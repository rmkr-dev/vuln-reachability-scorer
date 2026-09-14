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
