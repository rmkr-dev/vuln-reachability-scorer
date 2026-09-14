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
      "title": "string (optional)"
    }
  ]
}
```

## Edge endpoint checks

Edges whose `source` or `target` is not in `assets` produce a CLI **warning**. Pass `--strict` to treat those as errors (exit code 2).

## Tag boosts

Optional root object `tag_boosts` maps tag string → additive boost applied to `asset.criticality` before clamping to `[0, 1]`. Defaults live in `scoring.DEFAULT_TAG_BOOSTS` and are merged with any provided values.
