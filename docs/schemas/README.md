# Input schemas

Informal schemas for the JSON documents `vrscore` accepts. There is no JSON Schema runtime dependency; validation is performed in `loaders.py` / model constructors.

## topology.json

```json
{
  "tag_boosts": {"pii": 0.15, "identity": 0.2, "secrets": 0.2},
  "assets": [
    {
      "id": "string (required, unique)",
      "name": "string (optional; defaults to id)",
      "kind": "string (optional; default host)",
      "criticality": "number 0..1 (optional; default 0.5)",
      "tags": ["string"],
      "ingress": "boolean (optional; default false)"
    }
  ],
  "edges": [
    {
      "source": "asset id (required)",
      "target": "asset id (required)",
      "protocol": "string (optional; default network)",
      "internet_facing": "boolean (optional; default false; marks target as ingress)"
    }
  ]
}
```

## findings.json

Either a bare array or an object with a `findings` array:

```json
{
  "findings": [
    {
      "id": "string (required)",
      "asset_id": "string (required)",
      "cve_id": "string (optional; alias cve)",
      "base_score": "number 0..10 (required)",
      "title": "string (optional)",
      "kev": "boolean (optional; default false — Known Exploited Vulnerability multiplier)",
      "epss": "number 0..1 (optional; omitted = no EPSS adjustment — FIRST EPSS probability)"
    }
  ]
}
```

## Edge endpoint checks

Edges whose `source` or `target` is not in `assets` produce a CLI **warning**. Pass `--strict` to treat those as errors (exit code 2).

## Tag boosts

Optional root object `tag_boosts` maps tag string → additive boost applied to `asset.criticality` before clamping to `[0, 1]`. Defaults live in `scoring.DEFAULT_TAG_BOOSTS` and are merged with any provided values.


## EPSS

Optional finding field `epss` is a FIRST Exploit Prediction Scoring System probability in `[0, 1]`. When present, priority is multiplied by `1 + 0.20 × epss` and clamped to 10.0 after any KEV multiplier ([ADR-004](../decisions/ADR-004-epss-factor.md)). The CLI never fetches EPSS; operators supply the value. Omitting the field is a no-op.

## Loader errors

`loaders.py` wraps parse failures with the input kind and path:

- missing file → `topology file not found: <path>` (or `findings file not found`)
- empty / non-UTF-8 / invalid JSON → message includes the path and, for JSON, line/column
- missing required fields → `topology.assets[i]:` / `findings[i]:` plus the field names

## Config file

See [config.md](config.md) for `--config` / `-c` JSON and TOML keys ([ADR-006](../decisions/ADR-006-config-file.md)).
