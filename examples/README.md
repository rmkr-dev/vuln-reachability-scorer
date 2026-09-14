# Example inputs

Synthetic topology and findings for local demos. Asset names are fictional; CVE identifiers are real public records used only as severity illustrations.

```bash
vrscore --topology examples/topology.json --findings examples/findings.json
vrscore -t examples/topology.json -f examples/findings.json --format json
```

Expected shape: ingress (`edge-lb`) findings rank higher than equally severe findings on isolated or deep assets when criticality is similar.
